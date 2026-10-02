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
use std::path::PathBuf;

use nexus_storage::{ContentStore, ObjectId, object_id_of};

pub mod gc;

pub use gc::{
    AlwaysRun, DEFAULT_GC_INTERVAL_SECS, DEFAULT_MAX_SWEEP_PER_RUN, DEFAULT_RETENTION_SECS,
    DeepenReport, GcConfig, GcHandle, GcPlan, GcReason, GcReport, GcRoots, GcRunPolicy,
    GcScheduler, GcSchedulerConfig, InFlightGuard, InFlightSet, NoopQuotaHandler, ObjectFetcher,
    PackReport, QuotaHandler, QuotaPolicy, QuotaPressure, ReadOutcome, ReplicaPolicy,
    ShallowReport, Tombstone,
};

/// Workspace object cache (v9 §22): score-based eviction with pin iron rule.
pub mod cache;

/// Adapter: `WorkspaceAccess` → `nexus_platform::ProjectedWorkspace`
/// (portable projection contract consumed by `nexus-platform-*`).
pub mod projection_adapt;
pub use projection_adapt::WorkspaceProjection;

/// 合并事件：已找到合并基（Common Ancestor）。
pub const EV_COMMON_ANCESTOR_FOUND: &str = "common_ancestor_found";
/// 合并事件：已创建 Merge Commit。
pub const EV_MERGE_COMMIT_CREATED: &str = "merge_commit_created";

/// Workspace 标识（PRODUCT §4 权威模型字段）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub String);

/// 提交标识（v2 权威模型）：内容哈希，`hex16(fnv1a_64(canonical_bytes))`，
/// 与 CAS 的 `object_id_of` 同一哈希语义。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitId(pub String);

/// 提交作者/节点的不透明标识（v9 §17：Commit 含 Author/NodeId）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorId(pub String);

/// 内容哈希 CommitId（纯函数、确定性）。
///
/// 同一提交对象（parents + root + author + timestamp）在所有节点算出同一 ID，
/// 是跨端对账的基础；不同提交（任一输入不同）得不同 ID。
pub fn commit_id_of(
    parents: &[CommitId],
    root: &ObjectId,
    author: &AuthorId,
    created_at_unix: u64,
) -> CommitId {
    let mut parent_ids: Vec<&str> = parents.iter().map(|p| p.0.as_str()).collect();
    parent_ids.sort_unstable();
    let mut buf = String::from("nexus-commit-v1\n");
    buf.push_str("parents:");
    buf.push_str(&parent_ids.join(","));
    buf.push_str("\nroot:");
    buf.push_str(&root.0);
    buf.push_str("\nauthor:");
    buf.push_str(&author.0);
    buf.push_str("\ntimestamp:");
    buf.push_str(&created_at_unix.to_string());
    buf.push('\n');
    CommitId(object_id_of(buf.as_bytes()).0)
}

/// 冲突对象标识（纯函数、确定性）：`hex16(fnv1a_64(...))`。
pub fn conflict_id_of(
    base: &CommitId,
    local: &CommitId,
    remote: &CommitId,
    paths: &[String],
) -> String {
    let mut sorted = paths.to_vec();
    sorted.sort();
    let mut buf = String::from("nexus-conflict-v1\n");
    buf.push_str(&format!(
        "base:{}\nlocal:{}\nremote:{}\npaths:{}\n",
        base.0,
        local.0,
        remote.0,
        sorted.join(",")
    ));
    object_id_of(buf.as_bytes()).0
}

/// 不可变提交：parent(s) + 根 Manifest 的对象引用 + 作者 + 逻辑时间。
///
/// 提交一旦写入 DAG 不再变更；新内容只通过新建提交表达。
/// `id` 必须等于 `commit_id_of(parents, root_manifest_id, author, created_at_unix)`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCommit {
    pub id: CommitId,
    pub parents: Vec<CommitId>,
    pub root_manifest_id: ObjectId,
    pub author: AuthorId,
    pub created_at_unix: u64,
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

/// 持久化冲突对象（v9 §18）：冲突是 Workspace 状态的一部分，不是临时 UI 状态。
///
/// 字节进 CAS（内容寻址），索引进 `DurableState v2`（重启可恢复）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictObject {
    /// `conflict_id_of(base, local, remote, paths)`。
    pub id: String,
    pub base: CommitId,
    pub local: CommitId,
    pub remote: CommitId,
    /// 冲突路径（排序后）。
    pub paths: Vec<String>,
    pub state: ConflictState,
    /// 冲突对象字节在 CAS 中的 id。
    pub cas_object_id: ObjectId,
}

/// 冲突解决状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictState {
    Unresolved,
    Resolved { merge_commit: CommitId },
}

/// 单路径冲突的解决方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    TakeLocal,
    TakeRemote,
    Custom(Vec<u8>),
}

impl ConflictObject {
    /// 不可变创建记录字节（进 CAS）。解决状态是可变的，只存于工作区索引，
    /// 不进 CAS（CAS 不可变）。
    fn record_bytes(&self) -> Vec<u8> {
        let mut sorted = self.paths.clone();
        sorted.sort();
        let mut out = String::from("nexus-conflict-obj-v1\n");
        out.push_str(&format!("id {}\n", self.id));
        out.push_str(&format!("base {}\n", self.base.0));
        out.push_str(&format!("local {}\n", self.local.0));
        out.push_str(&format!("remote {}\n", self.remote.0));
        out.push_str(&format!("paths {}\n", sorted.join(",")));
        out.into_bytes()
    }
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
    pub author: AuthorId,
    pub created_at_unix: u64,
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
    /// 远程帧通道传输失败（remote P0：WorkspaceTransport 注入通道）。
    Transport { reason: String },
    /// 提供方拒绝远程提交（响应帧 `REJECTED`）。
    RemoteRejected { reason: String },
    /// 响应帧不符合 `OK:HEAD:<id>` / `REJECTED` 协议（不可吞为成功）。
    RemoteProtocol { frame: String },
    /// 读取或删除不存在的路径（投影通道语义）。
    NotFound { path: String },
    /// 路径越界（尝试访问物化目录外的文件）。
    PathTraversal { path: String },
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
            Self::Transport { reason } => write!(f, "remote transport failure: {reason}"),
            Self::RemoteRejected { reason } => write!(f, "remote workspace rejected: {reason}"),
            Self::RemoteProtocol { frame } => {
                write!(f, "unrecognized remote workspace frame: {frame:?}")
            }
            Self::NotFound { path } => write!(f, "path not found: {path}"),
            Self::PathTraversal { path } => write!(f, "path traversal blocked: {path}"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

/// Workspace 访问通道（PRODUCT §4：无 FUSE/Mount 环境仍可使用 Workspace）。
///
/// 访问通道只决定"如何看到/写入权威数据"，不改变权威模型本身
/// （Commit DAG + Head Set + Manifest 始终完整）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceAccessProvider {
    /// 平台原生目录挂载（FUSE / File Provider）。
    NativeMountDirectory,
    /// Materialization 物化目录（无 Mount 环境的投影通道）。
    MaterializedDirectory,
    /// 纯 Native API（结构化读写，不经文件系统投影；总可用兜底）。
    NativeApi,
}

impl WorkspaceAccessProvider {
    /// 稳定机器名（供 E4 场景机检，不随语言/展示变化）。
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NativeMountDirectory => "NativeMountDirectory",
            Self::MaterializedDirectory => "MaterializedDirectory",
            Self::NativeApi => "NativeApi",
        }
    }
}

/// 选择 Workspace 访问通道（纯函数、确定性，可重放）。
///
/// 优先级：Native Mount > Materialization > Native API（PRODUCT §4 的兜底通道，
/// 总可用）。所有通道都保持产品语义；`product_semantics_preserved` 是投影层
/// 的设计不变量，由组合根在 E4 场景中输出。
#[must_use]
pub fn select_access_provider(
    native_mount: bool,
    materialization: bool,
) -> WorkspaceAccessProvider {
    if native_mount {
        WorkspaceAccessProvider::NativeMountDirectory
    } else if materialization {
        WorkspaceAccessProvider::MaterializedDirectory
    } else {
        WorkspaceAccessProvider::NativeApi
    }
}

/// 目录条目（用于 list_dir）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// 条目路径（相对 workspace 根）
    pub path: String,
    /// 是否是目录
    pub is_dir: bool,
    /// 文件大小（字节），目录为 None
    pub size: Option<u64>,
}

/// Workspace 统一访问接口
///
/// 无论底层是 Mount、物化目录还是纯 API，用户都通过这个 trait 访问。
/// 访问通道只改变"怎么访问"，不改变权威模型（Commit DAG / Head Set / Manifest）。
pub trait WorkspaceAccess {
    /// 读取文件内容
    fn read_file(&self, path: &str) -> Result<Vec<u8>, WorkspaceError>;

    /// 写入文件内容（进入 WorkingSet）
    fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), WorkspaceError>;

    /// 列出目录内容
    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, WorkspaceError>;

    /// 删除文件/目录
    fn delete(&mut self, path: &str) -> Result<(), WorkspaceError>;

    /// 提交变更到 Workspace
    fn commit(&mut self) -> Result<CommitId, WorkspaceError>;

    /// 获取当前 Head
    fn head(&self) -> Option<&CommitId>;

    /// 获取当前访问通道类型
    fn provider_type(&self) -> WorkspaceAccessProvider;
}

/// 原生 API 通道（纯结构化读写，不经文件系统投影）
///
/// 这是兜底通道：任何平台都能用，包括 WASM、嵌入式等无文件系统环境。
///
/// 写入操作暂存于 WorkingSet（内存 HashMap），不立即落 Commit；
/// `commit` 时把 WorkingSet 暂存内容与删除集合落成新 Commit。
pub struct NativeApiWorkspaceAccess<S: ContentStore> {
    workspace: Workspace<S>,
    provider: WorkspaceAccessProvider,
    /// 暂存写入：path → content（尚未落 Commit）。
    staged_writes: HashMap<String, Vec<u8>>,
    /// 暂存删除：path（标记尚未落 Commit 的删除）。
    staged_deletes: HashSet<String>,
}

impl<S: ContentStore> NativeApiWorkspaceAccess<S> {
    /// 创建原生 API 通道
    pub fn new(workspace: Workspace<S>) -> Self {
        Self {
            workspace,
            provider: WorkspaceAccessProvider::NativeApi,
            staged_writes: HashMap::new(),
            staged_deletes: HashSet::new(),
        }
    }

    /// 消费访问通道，拿回内部 Workspace
    pub fn into_workspace(self) -> Workspace<S> {
        self.workspace
    }
}

impl<S: ContentStore> WorkspaceAccess for NativeApiWorkspaceAccess<S> {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, WorkspaceError> {
        // 暂存删除优先 → NotFound。
        if self.staged_deletes.contains(path) {
            return Err(WorkspaceError::NotFound {
                path: path.to_string(),
            });
        }
        // 暂存写入优先 → 返回 WorkingSet 内容。
        if let Some(content) = self.staged_writes.get(path) {
            return Ok(content.clone());
        }
        // 否则从当前 Head Manifest 经 ContentStore 读取。
        match self.workspace.read_from_head(path)? {
            Some(bytes) => Ok(bytes),
            None => Err(WorkspaceError::NotFound {
                path: path.to_string(),
            }),
        }
    }

    fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), WorkspaceError> {
        self.staged_writes
            .insert(path.to_string(), content.to_vec());
        self.staged_deletes.remove(path);
        Ok(())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, WorkspaceError> {
        // 获取当前 Head Manifest 的所有路径。
        let head_paths = self.workspace.list_head_paths()?;

        // 合并 WorkingSet：从 head_paths 构建初始集合。
        let mut merged: HashMap<String, u64> = HashMap::new();
        for p in &head_paths {
            if !self.staged_deletes.contains(p) {
                if let Some(bytes) = self.workspace.read_from_head(p)? {
                    merged.insert(p.clone(), bytes.len() as u64);
                }
            }
        }

        // 应用暂存写入。
        for (p, content) in &self.staged_writes {
            merged.insert(p.clone(), content.len() as u64);
        }

        // 移除暂存删除。
        for p in &self.staged_deletes {
            merged.remove(p);
        }

        // 单层列表：列出 path 目录下的直接子条目（合成父目录项）。
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{}/", path)
        };

        // 收集直接子条目：
        // - 文件：strip prefix 后无 '/' → 作为文件条目
        // - 目录：strip prefix 后有 '/' → 取第一段作为目录条目
        let mut entries_map: HashMap<String, (bool, Option<u64>)> = HashMap::new();

        for p in merged.keys() {
            if !p.starts_with(&prefix) {
                continue;
            }
            let relative = p.strip_prefix(&prefix).unwrap_or(p);
            if relative.is_empty() {
                continue;
            }
            // 取第一段（直接子条目名）。
            let first_segment = relative.split('/').next().unwrap_or(relative);
            // 判断是否是目录：存在其他路径以 first_segment/ 开头。
            let is_dir = merged
                .keys()
                .any(|q| q.starts_with(&format!("{prefix}{first_segment}/")));

            if is_dir {
                entries_map
                    .entry(first_segment.to_string())
                    .or_insert((true, None));
            } else {
                let size = merged.get(p).copied();
                entries_map
                    .entry(first_segment.to_string())
                    .or_insert((false, size));
            }
        }

        let mut entries: Vec<DirEntry> = entries_map
            .into_iter()
            .map(|(name, (is_dir, size))| DirEntry {
                path: name,
                is_dir,
                size,
            })
            .collect();

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn delete(&mut self, path: &str) -> Result<(), WorkspaceError> {
        // 检查是否存在（在 WorkingSet 或已提交内容中）。
        let exists = self.staged_writes.contains_key(path)
            || self.staged_deletes.contains(path)
            || self.workspace.read_from_head(path)?.is_some();
        if !exists {
            return Err(WorkspaceError::NotFound {
                path: path.to_string(),
            });
        }
        self.staged_writes.remove(path);
        self.staged_deletes.insert(path.to_string());
        Ok(())
    }

    fn commit(&mut self) -> Result<CommitId, WorkspaceError> {
        // 如果没有暂存变更，返回当前 Head。
        if self.staged_writes.is_empty() && self.staged_deletes.is_empty() {
            return self
                .workspace
                .heads()
                .heads
                .first()
                .cloned()
                .ok_or_else(|| WorkspaceError::StoreFailure {
                    reason: "no head to commit".into(),
                });
        }

        let head = self
            .workspace
            .heads()
            .heads
            .first()
            .cloned()
            .ok_or_else(|| WorkspaceError::StoreFailure {
                reason: "no head".into(),
            })?;
        let writes: Vec<Change> = self
            .staged_writes
            .iter()
            .map(|(path, content)| Change {
                path: path.clone(),
                content: content.clone(),
            })
            .collect();
        let deletes: Vec<String> = self.staged_deletes.iter().cloned().collect();

        let new_head = self
            .workspace
            .commit_with_deletes(&head, &writes, &deletes)?;

        // 清空 WorkingSet。
        self.staged_writes.clear();
        self.staged_deletes.clear();

        Ok(new_head)
    }

    fn head(&self) -> Option<&CommitId> {
        self.workspace.heads().heads.first()
    }

    fn provider_type(&self) -> WorkspaceAccessProvider {
        self.provider
    }
}

/// 物化目录通道（把 Workspace 当前 Head 物化到本地文件系统目录）
///
/// 无 Mount 环境下的投影通道：构造时把当前 Head 的全部文件物化到本地目录；
/// 读写操作直接走本地 FS；`commit` 时扫描差异落回 Workspace。
pub struct MaterializedDirectoryAccess<S: ContentStore> {
    workspace: Workspace<S>,
    dir: PathBuf,
    /// 物化时的路径快照（用于 commit 时计算删除差异）。
    materialized_paths: HashSet<String>,
    provider: WorkspaceAccessProvider,
}

impl<S: ContentStore> MaterializedDirectoryAccess<S> {
    /// 构造并物化：把 `workspace` 当前 Head 的全部文件写入 `dir`。
    ///
    /// 递归创建子目录；已存在的文件会被覆盖。
    pub fn materialize(workspace: Workspace<S>, dir: PathBuf) -> Result<Self, WorkspaceError> {
        // 创建根目录。
        std::fs::create_dir_all(&dir).map_err(|e| WorkspaceError::StoreFailure {
            reason: format!("create dir {}: {e}", dir.display()),
        })?;

        // 读取当前 Head 的所有路径。
        let paths = workspace.list_head_paths()?;
        let mut materialized_paths = HashSet::new();

        for path in &paths {
            let content =
                workspace
                    .read_from_head(path)?
                    .ok_or_else(|| WorkspaceError::MissingObject {
                        id: ObjectId(path.clone()),
                    })?;
            let file_path = dir.join(path);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| WorkspaceError::StoreFailure {
                    reason: format!("create parent {}: {e}", parent.display()),
                })?;
            }
            std::fs::write(&file_path, &content).map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("write {}: {e}", file_path.display()),
            })?;
            materialized_paths.insert(path.clone());
        }

        Ok(Self {
            workspace,
            dir,
            materialized_paths,
            provider: WorkspaceAccessProvider::MaterializedDirectory,
        })
    }

    /// 消费通道，拿回 Workspace 与目录路径。
    pub fn into_parts(self) -> (Workspace<S>, PathBuf) {
        (self.workspace, self.dir)
    }

    /// 验证路径安全：拒绝 `../`、绝对路径、Windows 盘符等越界路径。
    fn validate_path(path: &str) -> Result<(), WorkspaceError> {
        use std::path::Component;
        let p = PathBuf::from(path);
        for comp in p.components() {
            match comp {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(WorkspaceError::PathTraversal {
                        path: path.to_string(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// 递归扫描目录，收集所有相对路径文件。
    fn scan_dir(&self) -> Result<HashSet<String>, WorkspaceError> {
        let mut paths = HashSet::new();
        self.scan_recursive(&self.dir, "", &mut paths)?;
        Ok(paths)
    }

    fn scan_recursive(
        &self,
        base: &PathBuf,
        prefix: &str,
        out: &mut HashSet<String>,
    ) -> Result<(), WorkspaceError> {
        let entries = std::fs::read_dir(base).map_err(|e| WorkspaceError::StoreFailure {
            reason: format!("read dir {}: {e}", base.display()),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("dir entry: {e}"),
            })?;
            let path = entry.path();
            let rel = if prefix.is_empty() {
                entry.file_name().to_string_lossy().to_string()
            } else {
                format!("{}/{}", prefix, entry.file_name().to_string_lossy())
            };
            if path.is_dir() {
                self.scan_recursive(&path, &rel, out)?;
            } else {
                out.insert(rel);
            }
        }
        Ok(())
    }
}

impl<S: ContentStore> WorkspaceAccess for MaterializedDirectoryAccess<S> {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, WorkspaceError> {
        Self::validate_path(path)?;
        let file_path = self.dir.join(path);
        std::fs::read(&file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WorkspaceError::NotFound {
                    path: path.to_string(),
                }
            } else {
                WorkspaceError::StoreFailure {
                    reason: format!("read {}: {e}", file_path.display()),
                }
            }
        })
    }

    fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), WorkspaceError> {
        Self::validate_path(path)?;
        let file_path = self.dir.join(path);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("create parent {}: {e}", parent.display()),
            })?;
        }
        std::fs::write(&file_path, content).map_err(|e| WorkspaceError::StoreFailure {
            reason: format!("write {}: {e}", file_path.display()),
        })?;
        Ok(())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, WorkspaceError> {
        if !path.is_empty() {
            Self::validate_path(path)?;
        }
        let dir_path = if path.is_empty() {
            self.dir.clone()
        } else {
            self.dir.join(path)
        };
        let entries = std::fs::read_dir(&dir_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WorkspaceError::NotFound {
                    path: path.to_string(),
                }
            } else {
                WorkspaceError::StoreFailure {
                    reason: format!("read dir {}: {e}", dir_path.display()),
                }
            }
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("dir entry: {e}"),
            })?;
            let name = entry.file_name().to_string_lossy().to_string();
            let metadata = entry.metadata().map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("metadata: {e}"),
            })?;
            let is_dir = metadata.is_dir();
            let size = if is_dir { None } else { Some(metadata.len()) };
            result.push(DirEntry {
                path: name,
                is_dir,
                size,
            });
        }
        result.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    fn delete(&mut self, path: &str) -> Result<(), WorkspaceError> {
        Self::validate_path(path)?;
        let file_path = self.dir.join(path);
        std::fs::remove_file(&file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WorkspaceError::NotFound {
                    path: path.to_string(),
                }
            } else {
                WorkspaceError::StoreFailure {
                    reason: format!("delete {}: {e}", file_path.display()),
                }
            }
        })
    }

    fn commit(&mut self) -> Result<CommitId, WorkspaceError> {
        // 扫描当前目录文件。
        let current_paths = self.scan_dir()?;

        // 计算差异：
        // - 新增/修改：current_paths 中的文件，读取内容构建 Change。
        // - 删除：materialized_paths 中有但 current_paths 中没有的。
        let mut writes: Vec<Change> = Vec::new();
        let mut deletes: Vec<String> = Vec::new();

        for path in &current_paths {
            let file_path = self.dir.join(path);
            let content = std::fs::read(&file_path).map_err(|e| WorkspaceError::StoreFailure {
                reason: format!("read {}: {e}", file_path.display()),
            })?;
            writes.push(Change {
                path: path.clone(),
                content,
            });
        }

        for path in &self.materialized_paths {
            if !current_paths.contains(path) {
                deletes.push(path.clone());
            }
        }

        let head = self
            .workspace
            .heads()
            .heads
            .first()
            .cloned()
            .ok_or_else(|| WorkspaceError::StoreFailure {
                reason: "no head".into(),
            })?;
        let new_head = if writes.is_empty() && deletes.is_empty() {
            head
        } else {
            self.workspace
                .commit_with_deletes(&head, &writes, &deletes)?
        };

        // 更新物化快照。
        self.materialized_paths = current_paths;

        Ok(new_head)
    }

    fn head(&self) -> Option<&CommitId> {
        self.workspace.heads().heads.first()
    }

    fn provider_type(&self) -> WorkspaceAccessProvider {
        self.provider
    }
}

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

    /// 移除路径条目（如果存在）。
    fn remove(&mut self, path: &str) {
        self.entries.retain(|(p, _)| p != path);
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
    /// 若三方合并遇到显式冲突，给出持久化 ConflictObject 的 id（Head 集不变）。
    pub conflict: Option<String>,
    /// 合并前的 Head 数量（分叉判定）。
    pub head_count_before_merge: usize,
    /// 合并后不再可达的既有提交数（必须为 0：本地提交零丢失）。
    pub lost_successful_local_commits: usize,
}

/// 持久状态：DAG + Heads + Journal + Conflict 索引，序列化为单个 CAS 对象（原子替换）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableState {
    id: WorkspaceId,
    commits: Vec<WorkspaceCommit>,
    heads: Vec<CommitId>,
    journal: Vec<JournalEntry>,
    tombstones: Vec<Tombstone>,
    retained: Vec<CommitId>,
    holds: Vec<ObjectId>,
    shallow_frontier: Vec<CommitId>,
    conflicts: Vec<ConflictObject>,
}

impl DurableState {
    const HEADER: &'static str = "nexus-workspace-state v2";
    /// W1 旧状态兼容垫片：W1 写入的状态在 HEADER 后带此行，只读不写；
    /// from_bytes 遇到时跳过（v9 §17/§18 authority-v2 requirement-change 后不再写入）。
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
                "commit {} {} parents:{} author:{} ts:{}\n",
                c.id.0, c.root_manifest_id.0, parents, c.author.0, c.created_at_unix
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
                "journal {} {} {action} parents:{} author:{} ts:{}\n",
                e.commit_id.0, e.root_manifest_id.0, parents, e.author.0, e.created_at_unix
            ));
        }
        for cf in &self.conflicts {
            let state = match &cf.state {
                ConflictState::Unresolved => "unresolved".to_string(),
                ConflictState::Resolved { merge_commit } => {
                    format!("resolved:{}", merge_commit.0)
                }
            };
            out.push_str(&format!(
                "conflict {} {} {} {} {} {state}\n",
                cf.id,
                cf.base.0,
                cf.local.0,
                cf.remote.0,
                cf.paths.join(","),
            ));
        }
        for t in &self.tombstones {
            out.push_str(&format!(
                "tombstone {} {} {}\n",
                t.object_id.0,
                t.tombstoned_at_unix,
                t.reason.as_str()
            ));
        }
        for r in &self.retained {
            out.push_str(&format!("retain {}\n", r.0));
        }
        for h in &self.holds {
            out.push_str(&format!("hold {}\n", h.0));
        }
        for f in &self.shallow_frontier {
            out.push_str(&format!("shallow {}\n", f.0));
        }
        out.into_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, WorkspaceError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| WorkspaceError::CorruptState {
                reason: format!("state not utf8: {e}"),
            })?
            .to_string();
        let mut lines = text.lines();
        let header = lines.next().unwrap_or("");
        if header != Self::HEADER {
            return Err(WorkspaceError::CorruptState {
                reason: format!(
                    "unsupported state version: {header:?}, expected {:?} (v1 state is not auto-migrated)",
                    Self::HEADER
                ),
            });
        }
        let mut id = None;
        let mut commits = Vec::new();
        let mut heads = Vec::new();
        let mut journal = Vec::new();
        let mut tombstones = Vec::new();
        let mut retained = Vec::new();
        let mut holds = Vec::new();
        let mut shallow_frontier = Vec::new();
        let mut conflicts = Vec::new();
        for line in lines {
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
                    let mut parents = Vec::new();
                    let mut author = AuthorId(String::new());
                    let mut ts = 0u64;
                    for tok in t {
                        if let Some(p) = tok.strip_prefix("parents:") {
                            parents = p
                                .split(',')
                                .filter(|s| !s.is_empty())
                                .map(|s| CommitId(s.to_string()))
                                .collect();
                        } else if let Some(a) = tok.strip_prefix("author:") {
                            author = AuthorId(a.to_string());
                        } else if let Some(s) = tok.strip_prefix("ts:") {
                            ts = s.parse().map_err(|_| WorkspaceError::CorruptState {
                                reason: format!("commit {raw_id} bad ts"),
                            })?;
                        } else {
                            return Err(WorkspaceError::CorruptState {
                                reason: format!("commit {raw_id} unexpected token {tok}"),
                            });
                        }
                    }
                    commits.push(WorkspaceCommit {
                        id: CommitId(raw_id.to_string()),
                        parents,
                        root_manifest_id: ObjectId(raw_manifest.to_string()),
                        author,
                        created_at_unix: ts,
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
                    let parents = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("journal {raw_id} lacks parents"),
                    })?;
                    let parents = parents
                        .strip_prefix("parents:")
                        .ok_or_else(|| WorkspaceError::CorruptState {
                            reason: format!("journal {raw_id} bad parents token"),
                        })?
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(|p| CommitId(p.to_string()))
                        .collect::<Vec<_>>();
                    let mut author = AuthorId(String::new());
                    let mut ts = 0u64;
                    for tok in t {
                        if let Some(a) = tok.strip_prefix("author:") {
                            author = AuthorId(a.to_string());
                        } else if let Some(s) = tok.strip_prefix("ts:") {
                            ts = s.parse().map_err(|_| WorkspaceError::CorruptState {
                                reason: format!("journal {raw_id} bad ts"),
                            })?;
                        } else {
                            return Err(WorkspaceError::CorruptState {
                                reason: format!("journal {raw_id} unexpected token {tok}"),
                            });
                        }
                    }
                    journal.push(JournalEntry {
                        commit_id: CommitId(raw_id.to_string()),
                        parents,
                        root_manifest_id: ObjectId(raw_manifest.to_string()),
                        author,
                        created_at_unix: ts,
                        head_action,
                    });
                }
                Some(line) if line == Self::HEADER_TOKEN => {}
                Some("tombstone") => {
                    let raw_id = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "tombstone line lacks object id".into(),
                    })?;
                    let raw_ts = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "tombstone line lacks timestamp".into(),
                    })?;
                    let raw_reason = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "tombstone line lacks reason".into(),
                    })?;
                    let tombstoned_at_unix =
                        raw_ts
                            .parse::<u64>()
                            .map_err(|_| WorkspaceError::CorruptState {
                                reason: format!("tombstone has bad timestamp {raw_ts}"),
                            })?;
                    let reason = GcReason::parse(raw_reason).ok_or_else(|| {
                        WorkspaceError::CorruptState {
                            reason: format!("tombstone has bad reason {raw_reason}"),
                        }
                    })?;
                    tombstones.push(Tombstone {
                        object_id: ObjectId(raw_id.to_string()),
                        tombstoned_at_unix,
                        reason,
                    });
                }
                Some("retain") => {
                    let raw = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "retain line lacks commit id".into(),
                    })?;
                    retained.push(CommitId(raw.to_string()));
                }
                Some("hold") => {
                    let raw = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "hold line lacks object id".into(),
                    })?;
                    holds.push(ObjectId(raw.to_string()));
                }
                Some("shallow") => {
                    let raw = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "shallow line lacks commit id".into(),
                    })?;
                    shallow_frontier.push(CommitId(raw.to_string()));
                }
                Some("conflict") => {
                    let cid = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "conflict line lacks id".into(),
                    })?;
                    let base = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("conflict {cid} lacks base"),
                    })?;
                    let local = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("conflict {cid} lacks local"),
                    })?;
                    let remote = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("conflict {cid} lacks remote"),
                    })?;
                    let paths = t
                        .next()
                        .unwrap_or("")
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>();
                    let state_tok = t.next().unwrap_or("unresolved");
                    let state = if state_tok == "unresolved" {
                        ConflictState::Unresolved
                    } else if let Some(mid) = state_tok.strip_prefix("resolved:") {
                        ConflictState::Resolved {
                            merge_commit: CommitId(mid.to_string()),
                        }
                    } else {
                        return Err(WorkspaceError::CorruptState {
                            reason: format!("conflict {cid} bad state"),
                        });
                    };
                    // cas 对象 id 在打开时按需从 CAS 重算（内容寻址，确定性）。
                    let obj = ConflictObject {
                        id: cid.to_string(),
                        base: CommitId(base.to_string()),
                        local: CommitId(local.to_string()),
                        remote: CommitId(remote.to_string()),
                        paths,
                        state,
                        cas_object_id: ObjectId(String::new()),
                    };
                    conflicts.push(obj);
                }
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
        // 恢复冲突对象的 CAS id（内容寻址确定性重算；CAS 存不可变创建记录）。
        for cf in &mut conflicts {
            let probe = ConflictObject {
                id: cf.id.clone(),
                base: cf.base.clone(),
                local: cf.local.clone(),
                remote: cf.remote.clone(),
                paths: cf.paths.clone(),
                state: ConflictState::Unresolved,
                cas_object_id: ObjectId(String::new()),
            };
            cf.cas_object_id = object_id_of(&probe.record_bytes());
        }
        Ok(Self {
            id,
            commits,
            heads,
            journal,
            tombstones,
            retained,
            holds,
            shallow_frontier,
            conflicts,
        })
    }
}

/// Workspace 权威状态：不可变 Commit DAG + Head Set + 内容寻址存储 + 写前日志。
#[derive(Debug)]
pub struct Workspace<S: ContentStore> {
    id: WorkspaceId,
    author: AuthorId,
    commits: HashMap<CommitId, WorkspaceCommit>,
    heads: HeadSet,
    store: S,
    /// 当前持久状态对象（DAG + Heads + Journal + Conflict 索引）。
    state_root: ObjectId,
    /// 写前日志（未确认的 pending 提交 marker）。
    journal: Vec<JournalEntry>,
    /// GC Tombstone / Deletion Intent（v9 §20，持久态）。
    tombstones: Vec<Tombstone>,
    /// 显式保留的 Snapshot（GC Protected Root，持久态）。
    retained: Vec<CommitId>,
    /// Legal / user hold（GC Protected Root，持久态）。
    holds: Vec<ObjectId>,
    /// Active pin（内存态，进程持有）。
    pins: HashSet<ObjectId>,
    /// 本地 Replica 策略（shallow/sparse）。
    replica_policy: ReplicaPolicy,
    /// 未持有的父提交（shallow ancestry frontier）。
    shallow_frontier: Vec<CommitId>,
    /// 持久化冲突索引（v9 §18；字节进 CAS，索引进 DurableState）。
    conflicts: HashMap<String, ConflictObject>,
}

impl<S: ContentStore> Workspace<S> {
    /// 当前 unix 秒（逻辑元数据；提交 ID 哈希输入的一部分）。
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 新建 Workspace：创建空 Manifest 的创世提交（内容哈希 ID），Head 为其，
    /// 并持久化初始状态。
    pub fn init(id: WorkspaceId, mut store: S, author: AuthorId) -> Result<Self, WorkspaceError> {
        let empty = Manifest::default();
        let root_manifest_id = store
            .put(&empty.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        let created_at_unix = Self::now_unix();
        let base = WorkspaceCommit {
            id: commit_id_of(&[], &root_manifest_id, &author, created_at_unix),
            parents: Vec::new(),
            root_manifest_id,
            author: author.clone(),
            created_at_unix,
        };
        let mut ws = Self {
            id,
            author,
            commits: HashMap::new(),
            heads: HeadSet::default(),
            store,
            state_root: ObjectId(String::new()),
            journal: Vec::new(),
            tombstones: Vec::new(),
            retained: Vec::new(),
            holds: Vec::new(),
            pins: HashSet::new(),
            replica_policy: ReplicaPolicy::default(),
            shallow_frontier: Vec::new(),
            conflicts: HashMap::new(),
        };
        ws.commits.insert(base.id.clone(), base.clone());
        ws.heads.add(base.id.clone());
        ws.persist_state()?;
        Ok(ws)
    }

    /// 冷启动：从持久状态对象恢复 Workspace（AGENTS.md §15：先加载 durable state）。
    ///
    /// v1 状态（`C{seq}` 序列 ID）被拒绝，不自动迁移。
    pub fn open(
        id: WorkspaceId,
        store: S,
        state_root: &ObjectId,
        author: AuthorId,
    ) -> Result<Self, WorkspaceError> {
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
            // 防篡改：持久化的提交 ID 必须与其内容哈希一致。
            let expect = commit_id_of(
                &c.parents,
                &c.root_manifest_id,
                &c.author,
                c.created_at_unix,
            );
            if expect != c.id {
                return Err(WorkspaceError::CorruptState {
                    reason: format!("commit id {:?} does not match content hash", c.id),
                });
            }
            commits.insert(c.id.clone(), c.clone());
        }
        let mut heads = HeadSet::default();
        for h in &state.heads {
            heads.add(h.clone());
        }
        let mut conflicts = HashMap::new();
        for cf in state.conflicts {
            conflicts.insert(cf.id.clone(), cf);
        }
        Ok(Self {
            id,
            author,
            commits,
            heads,
            store,
            state_root: state_root.clone(),
            journal: state.journal,
            tombstones: state.tombstones,
            retained: state.retained,
            holds: state.holds,
            pins: HashSet::new(),
            replica_policy: ReplicaPolicy::default(),
            shallow_frontier: state.shallow_frontier,
            conflicts,
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

    /// 底层存储的只读访问（E4/测试：跨端 store 克隆、CAS 断言）。
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// 按 id 读取提交（只读 DAG 查询）。
    #[must_use]
    pub fn commit(&self, id: &CommitId) -> Option<&WorkspaceCommit> {
        self.commits.get(id)
    }

    /// 把当前内存状态（DAG + Heads + Journal + GC 状态）持久化为单个 CAS 对象。
    fn persist_state(&mut self) -> Result<ObjectId, WorkspaceError> {
        let mut commits: Vec<WorkspaceCommit> = self.commits.values().cloned().collect();
        commits.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        let mut tombstones = self.tombstones.clone();
        tombstones.sort_by(|a, b| a.object_id.0.cmp(&b.object_id.0));
        let mut retained = self.retained.clone();
        retained.sort_by(|a, b| a.0.cmp(&b.0));
        let mut holds = self.holds.clone();
        holds.sort_by(|a, b| a.0.cmp(&b.0));
        let mut shallow_frontier = self.shallow_frontier.clone();
        shallow_frontier.sort_by(|a, b| a.0.cmp(&b.0));
        let mut conflicts: Vec<ConflictObject> = self.conflicts.values().cloned().collect();
        conflicts.sort_by(|a, b| a.id.cmp(&b.id));
        let state = DurableState {
            id: self.id.clone(),
            commits,
            heads: self.heads.heads.clone(),
            journal: self.journal.clone(),
            tombstones,
            retained,
            holds,
            shallow_frontier,
            conflicts,
        };
        let oid = self
            .store
            .put(&state.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        self.state_root = oid.clone();
        Ok(oid)
    }

    /// 写前登记：为一次“即将落 DAG”的提交写入 journal marker（marker 落盘，
    /// 提交尚未可见）。返回新提交 id（内容哈希）；随后应调用 `commit_pending` 完成写入。
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
        let created_at_unix = Self::now_unix();
        let id = commit_id_of(
            std::slice::from_ref(parent),
            &root_manifest_id,
            &self.author,
            created_at_unix,
        );
        let head_action = if self.heads.contains(parent) {
            HeadAction::Replace(parent.clone())
        } else {
            HeadAction::Add
        };
        self.journal.push(JournalEntry {
            commit_id: id.clone(),
            parents: vec![parent.clone()],
            root_manifest_id,
            author: self.author.clone(),
            created_at_unix,
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
            author: entry.author.clone(),
            created_at_unix: entry.created_at_unix,
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

    /// 带删除的离线写入：写前登记 + 完成提交，支持同时写入和删除路径。
    ///
    /// `writes` 中的路径会被写入或覆盖；`deletes` 中的路径会从新 Manifest 移除。
    /// 其余语义与 `commit_changes` 相同。
    pub fn commit_with_deletes(
        &mut self,
        parent: &CommitId,
        writes: &[Change],
        deletes: &[String],
    ) -> Result<CommitId, WorkspaceError> {
        let parent_commit = self
            .commits
            .get(parent)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: parent.clone() })?;
        let mut manifest = self.load_manifest(&parent_commit.root_manifest_id)?;
        for change in writes {
            let oid = self
                .store
                .put(&change.content)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
            manifest.set(change.path.clone(), oid);
        }
        for path in deletes {
            manifest.remove(path);
        }
        let root_manifest_id = self
            .store
            .put(&manifest.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        let created_at_unix = Self::now_unix();
        let id = commit_id_of(
            std::slice::from_ref(parent),
            &root_manifest_id,
            &self.author,
            created_at_unix,
        );
        let head_action = if self.heads.contains(parent) {
            HeadAction::Replace(parent.clone())
        } else {
            HeadAction::Add
        };
        self.journal.push(JournalEntry {
            commit_id: id.clone(),
            parents: vec![parent.clone()],
            root_manifest_id,
            author: self.author.clone(),
            created_at_unix,
            head_action,
        });
        // 写前日志：marker 先落盘，然后立即完成提交（marker 清除）。
        self.persist_state()?;
        self.commit_pending(&id)
    }

    /// 从当前 Head 的 Manifest 读取文件内容。
    ///
    /// 返回 `Ok(None)` 表示路径不存在于当前 Head。
    pub fn read_from_head(&self, path: &str) -> Result<Option<Vec<u8>>, WorkspaceError> {
        let head = self
            .heads
            .heads
            .first()
            .ok_or_else(|| WorkspaceError::StoreFailure {
                reason: "no head commit".into(),
            })?;
        let commit = self
            .commits
            .get(head)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: head.clone() })?;
        let manifest = self.load_manifest(&commit.root_manifest_id)?;
        match manifest.get(path) {
            Some(oid) => {
                let bytes = self
                    .store
                    .get(oid)
                    .map_err(|reason| WorkspaceError::StoreFailure { reason })?
                    .ok_or_else(|| WorkspaceError::MissingObject { id: oid.clone() })?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// 列出当前 Head Manifest 中的所有文件路径。
    pub fn list_head_paths(&self) -> Result<Vec<String>, WorkspaceError> {
        let head = self
            .heads
            .heads
            .first()
            .ok_or_else(|| WorkspaceError::StoreFailure {
                reason: "no head commit".into(),
            })?;
        let commit = self
            .commits
            .get(head)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: head.clone() })?;
        let manifest = self.load_manifest(&commit.root_manifest_id)?;
        Ok(manifest.entries.iter().map(|(p, _)| p.clone()).collect())
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
                author: entry.author.clone(),
                created_at_unix: entry.created_at_unix,
            };
            self.commits.insert(entry.commit_id.clone(), commit);
            match &entry.head_action {
                HeadAction::Replace(old) => self.heads.replace(old, entry.commit_id.clone()),
                HeadAction::Add => self.heads.add(entry.commit_id.clone()),
            }
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
                conflict: None,
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
                conflict: None,
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
                conflict: None,
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
        // v9 §18：冲突落为持久化 ConflictObject（进 CAS），是 Workspace 状态的一部分；
        // merge_heads 不再以 Err 返回，Head 集不变，等待显式 resolve_conflict。
        let mut conflict_paths: Vec<String> = Vec::new();
        for (path, local_id) in &local_delta {
            if let Some((_, remote_id)) = remote_delta.iter().find(|(p, _)| p == path) {
                if remote_id != local_id {
                    conflict_paths.push(path.clone());
                }
            }
        }
        if !conflict_paths.is_empty() {
            conflict_paths.sort();
            let conflict_id = conflict_id_of(&base, local, remote, &conflict_paths);
            // 幂等：同一三元组重复合并复用已持久化的冲突对象。
            if !self.conflicts.contains_key(&conflict_id) {
                let mut obj = ConflictObject {
                    id: conflict_id.clone(),
                    base: base.clone(),
                    local: local.clone(),
                    remote: remote.clone(),
                    paths: conflict_paths.clone(),
                    state: ConflictState::Unresolved,
                    cas_object_id: ObjectId(String::new()),
                };
                let cas_id = self
                    .store
                    .put(&obj.record_bytes())
                    .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
                obj.cas_object_id = cas_id;
                self.conflicts.insert(conflict_id.clone(), obj);
                self.persist_state()?;
            }
            let post_reachable = self.reachable_from(&self.heads.heads.clone());
            let lost = pre_reachable.difference(&post_reachable).count();
            return Ok(MergeReport {
                disposition: MergeDisposition::Diverged,
                events,
                merge_commit: None,
                conflict: Some(conflict_id),
                head_count_before_merge,
                lost_successful_local_commits: lost,
            });
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
        let created_at_unix = Self::now_unix();
        let parents = vec![local.clone(), remote.clone()];
        let id = commit_id_of(&parents, &root_manifest_id, &self.author, created_at_unix);
        let merge_commit = WorkspaceCommit {
            id: id.clone(),
            parents,
            root_manifest_id,
            author: self.author.clone(),
            created_at_unix,
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
            conflict: None,
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

    /// 按 id 读取持久化冲突对象。
    #[must_use]
    pub fn get_conflict(&self, conflict_id: &str) -> Option<&ConflictObject> {
        self.conflicts.get(conflict_id)
    }

    /// 显式解决冲突：按 `resolutions` 逐冲突路径取值，生成 Merge Commit
    /// （内容哈希 ID，parents = [local, remote]），标记冲突为 Resolved，
    /// Heads 收敛。未覆盖的冲突路径保持未解决（返回错误，不落提交）。
    pub fn resolve_conflict(
        &mut self,
        conflict_id: &str,
        resolutions: &[(String, ConflictResolution)],
    ) -> Result<CommitId, WorkspaceError> {
        let conflict = self.conflicts.get(conflict_id).cloned().ok_or_else(|| {
            WorkspaceError::MergeConflict(MergeConflict::ConflictingPath {
                path: format!("<unknown conflict {conflict_id}>"),
            })
        })?;
        if !matches!(conflict.state, ConflictState::Unresolved) {
            return Err(WorkspaceError::MergeConflict(
                MergeConflict::ConflictingPath {
                    path: format!("<conflict {conflict_id} already resolved>"),
                },
            ));
        }
        if resolutions.len() != conflict.paths.len()
            || !resolutions.iter().all(|(p, _)| conflict.paths.contains(p))
        {
            return Err(WorkspaceError::MergeConflict(
                MergeConflict::ConflictingPath {
                    path: "<resolutions must cover exactly the conflicting paths>".into(),
                },
            ));
        }
        let base_commit =
            self.commits
                .get(&conflict.base)
                .ok_or_else(|| WorkspaceError::UnknownCommit {
                    id: conflict.base.clone(),
                })?;
        let local_commit =
            self.commits
                .get(&conflict.local)
                .ok_or_else(|| WorkspaceError::UnknownCommit {
                    id: conflict.local.clone(),
                })?;
        let remote_commit =
            self.commits
                .get(&conflict.remote)
                .ok_or_else(|| WorkspaceError::UnknownCommit {
                    id: conflict.remote.clone(),
                })?;
        let base_manifest = self.load_manifest(&base_commit.root_manifest_id)?;
        let local_manifest = self.load_manifest(&local_commit.root_manifest_id)?;
        let remote_manifest = self.load_manifest(&remote_commit.root_manifest_id)?;
        let local_delta = local_manifest.diff_from(&base_manifest);
        let remote_delta = remote_manifest.diff_from(&base_manifest);

        let mut merged = base_manifest;
        for (path, id) in local_delta.iter().chain(remote_delta.iter()) {
            if !conflict.paths.contains(path) {
                merged.set(path.clone(), id.clone());
            }
        }
        for (path, resolution) in resolutions {
            let oid = match resolution {
                ConflictResolution::TakeLocal => local_manifest
                    .get(path)
                    .cloned()
                    .ok_or_else(|| WorkspaceError::NotFound { path: path.clone() })?,
                ConflictResolution::TakeRemote => remote_manifest
                    .get(path)
                    .cloned()
                    .ok_or_else(|| WorkspaceError::NotFound { path: path.clone() })?,
                ConflictResolution::Custom(bytes) => self
                    .store
                    .put(bytes)
                    .map_err(|reason| WorkspaceError::StoreFailure { reason })?,
            };
            merged.set(path.clone(), oid);
        }
        let root_manifest_id = self
            .store
            .put(&merged.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        let created_at_unix = Self::now_unix();
        let parents = vec![conflict.local.clone(), conflict.remote.clone()];
        let id = commit_id_of(&parents, &root_manifest_id, &self.author, created_at_unix);
        let commit = WorkspaceCommit {
            id: id.clone(),
            parents,
            root_manifest_id,
            author: self.author.clone(),
            created_at_unix,
        };
        self.commits.insert(id.clone(), commit);
        self.heads.remove(&conflict.local);
        self.heads.remove(&conflict.remote);
        self.heads.add(id.clone());
        if let Some(cf) = self.conflicts.get_mut(conflict_id) {
            cf.state = ConflictState::Resolved {
                merge_commit: id.clone(),
            };
        }
        self.persist_state()?;
        Ok(id)
    }

    // ---- Head 交换与同步（基于 WorkspaceTransport 帧通道） ----

    /// 与对端交换 Head Set（只交换，不拉取/合并）。
    pub fn exchange_heads(
        &mut self,
        transport: &mut dyn WorkspaceTransport,
    ) -> Result<HeadExchangeReport, WorkspaceError> {
        self.exchange_heads_inner(transport)
    }

    /// 与对端交换 Head Set（主动端调用一半；被动端由 `serve_sync` 应答）。
    fn exchange_heads_inner(
        &self,
        transport: &mut dyn WorkspaceTransport,
    ) -> Result<HeadExchangeReport, WorkspaceError> {
        let local_heads = self.heads.heads.clone();
        let ids = local_heads
            .iter()
            .map(|h| h.0.as_str())
            .collect::<Vec<_>>()
            .join(",");
        transport.send_frame(format!("HEADS:{ids}").as_bytes())?;
        let ack = transport.recv_frame()?;
        let text = String::from_utf8(ack).map_err(|_| WorkspaceError::RemoteProtocol {
            frame: "<non-utf8>".into(),
        })?;
        let rest =
            text.strip_prefix("HEADS-ACK:")
                .ok_or_else(|| WorkspaceError::RemoteProtocol {
                    frame: text.clone(),
                })?;
        let remote_heads = rest
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| CommitId(s.to_string()))
            .collect();
        Ok(HeadExchangeReport {
            local_heads,
            remote_heads,
        })
    }

    /// 主动同步：交换 Head → 拉取缺失提交（含 manifest）→ 逐对 merge_heads 收敛。
    ///
    /// 收到的提交逐个校验 `id == hash(content)`，不通过则拒绝（`CorruptState`）。
    pub fn sync_with_remote(
        &mut self,
        transport: &mut dyn WorkspaceTransport,
    ) -> Result<SyncReport, WorkspaceError> {
        let exchange = self.exchange_heads_inner(transport)?;
        // 拉取缺失提交：BFS 自远端 head，排除本地已有，迭代至闭包。
        let mut fetched_commits = 0usize;
        let mut want: Vec<CommitId> = exchange
            .remote_heads
            .iter()
            .filter(|h| !self.commits.contains_key(h))
            .cloned()
            .collect();
        let mut want_ids: Vec<String> = want.iter().map(|c| c.0.clone()).collect();
        while !want_ids.is_empty() {
            transport.send_frame(format!("WANT-COMMITS:{}", want_ids.join(",")).as_bytes())?;
            let n = Self::recv_count(transport, "COMMITS:")?;
            for _ in 0..n {
                let frame = transport.recv_frame()?;
                let commit = Self::parse_commit_frame(&frame)?;
                let expect = commit_id_of(
                    &commit.parents,
                    &commit.root_manifest_id,
                    &commit.author,
                    commit.created_at_unix,
                );
                if expect != commit.id {
                    return Err(WorkspaceError::CorruptState {
                        reason: format!(
                            "remote commit id {:?} does not match content hash",
                            commit.id
                        ),
                    });
                }
                for p in &commit.parents {
                    if !self.commits.contains_key(p)
                        && !want.iter().any(|w| w == p)
                        && !want_ids.iter().any(|w| w == &p.0)
                    {
                        want.push(p.clone());
                    }
                }
                self.commits.insert(commit.id.clone(), commit);
                fetched_commits += 1;
            }
            want_ids = want
                .iter()
                .filter(|c| !self.commits.contains_key(c))
                .map(|c| c.0.clone())
                .collect();
        }
        // 拉取新提交的 manifest（blob 按需，读时再取）。
        let mut want_objs: Vec<String> = Vec::new();
        for c in self.commits.values() {
            let mid = c.root_manifest_id.0.clone();
            if self
                .store
                .contains(&c.root_manifest_id)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            {
                continue;
            }
            if !want_objs.contains(&mid) {
                want_objs.push(mid);
            }
        }
        let mut fetched_objects = 0usize;
        if !want_objs.is_empty() {
            transport.send_frame(format!("WANT-OBJECTS:{}", want_objs.join(",")).as_bytes())?;
            let n = Self::recv_count(transport, "OBJECTS:")?;
            for _ in 0..n {
                let frame = transport.recv_frame()?;
                let (id, bytes) = Self::parse_object_frame(&frame)?;
                self.store
                    .put(&bytes)
                    .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
                let _ = id;
                fetched_objects += 1;
            }
        }
        transport.send_frame(b"SYNC-DONE")?;

        // 逐对合并：每个远端 head 与本地首个 head 配对。
        let mut disposition = MergeDisposition::AlreadyEqual;
        let mut common_ancestor = None;
        let mut conflict = None;
        let mut merge_commit = None;
        for rhead in &exchange.remote_heads {
            if self.heads.contains(rhead) {
                continue;
            }
            let lhead =
                self.heads
                    .heads
                    .first()
                    .cloned()
                    .ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "no local head to merge with".into(),
                    })?;
            common_ancestor = self.find_common_ancestor(&lhead, rhead)?;
            let report = self.merge_heads(&lhead, rhead)?;
            disposition = report.disposition.clone();
            if report.conflict.is_some() {
                conflict = report.conflict.clone();
            }
            if report.merge_commit.is_some() {
                merge_commit = report.merge_commit.clone();
            }
        }
        Ok(SyncReport {
            remote_heads: exchange.remote_heads,
            fetched_commits,
            fetched_objects,
            disposition,
            common_ancestor,
            conflict,
            merge_commit,
        })
    }

    /// 被动端：应答一次完整同步会话（HEADS/WANT-COMMITS/WANT-OBJECTS），收到
    /// SYNC-DONE 后返回。本端不主动合并（由主动端发起下一轮或本地 merge_heads）。
    pub fn serve_sync(
        &mut self,
        transport: &mut dyn WorkspaceTransport,
    ) -> Result<SyncServedReport, WorkspaceError> {
        let mut served_commits = 0usize;
        let mut served_objects = 0usize;
        loop {
            let frame = transport.recv_frame()?;
            let text = String::from_utf8(frame).map_err(|_| WorkspaceError::RemoteProtocol {
                frame: "<non-utf8>".into(),
            })?;
            if let Some(rest) = text.strip_prefix("HEADS:") {
                let _ = rest;
                let ids = self
                    .heads
                    .heads
                    .iter()
                    .map(|h| h.0.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                transport.send_frame(format!("HEADS-ACK:{ids}").as_bytes())?;
            } else if let Some(rest) = text.strip_prefix("WANT-COMMITS:") {
                let ids: Vec<&str> = rest.split(',').filter(|s| !s.is_empty()).collect();
                transport.send_frame(format!("COMMITS:{}", ids.len()).as_bytes())?;
                for id in ids {
                    let commit = self.commits.get(&CommitId(id.to_string())).ok_or_else(|| {
                        WorkspaceError::RemoteProtocol {
                            frame: format!("unknown commit requested: {id}"),
                        }
                    })?;
                    transport.send_frame(&Self::commit_to_frame(commit))?;
                    served_commits += 1;
                }
            } else if let Some(rest) = text.strip_prefix("WANT-OBJECTS:") {
                let ids: Vec<&str> = rest.split(',').filter(|s| !s.is_empty()).collect();
                transport.send_frame(format!("OBJECTS:{}", ids.len()).as_bytes())?;
                for id in ids {
                    let bytes = self
                        .store
                        .get(&ObjectId(id.to_string()))
                        .map_err(|reason| WorkspaceError::StoreFailure { reason })?
                        .ok_or_else(|| WorkspaceError::MissingObject {
                            id: ObjectId(id.to_string()),
                        })?;
                    transport
                        .send_frame(format!("OBJECT-DATA:{id}:{}", hex_bytes(&bytes)).as_bytes())?;
                    served_objects += 1;
                }
            } else if text == "SYNC-DONE" {
                break;
            } else {
                return Err(WorkspaceError::RemoteProtocol { frame: text });
            }
        }
        Ok(SyncServedReport {
            served_commits,
            served_objects,
        })
    }

    fn recv_count(
        transport: &mut dyn WorkspaceTransport,
        prefix: &str,
    ) -> Result<usize, WorkspaceError> {
        let frame = transport.recv_frame()?;
        let text = String::from_utf8(frame).map_err(|_| WorkspaceError::RemoteProtocol {
            frame: "<non-utf8>".into(),
        })?;
        text.strip_prefix(prefix)
            .ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?
            .parse()
            .map_err(|_| WorkspaceError::RemoteProtocol { frame: text })
    }

    fn commit_to_frame(commit: &WorkspaceCommit) -> Vec<u8> {
        let parents = commit
            .parents
            .iter()
            .map(|p| p.0.as_str())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "COMMIT:{}\nparents:{parents}\nroot:{}\nauthor:{}\nts:{}\n",
            commit.id.0, commit.root_manifest_id.0, commit.author.0, commit.created_at_unix
        )
        .into_bytes()
    }

    fn parse_commit_frame(frame: &[u8]) -> Result<WorkspaceCommit, WorkspaceError> {
        let text =
            String::from_utf8(frame.to_vec()).map_err(|_| WorkspaceError::RemoteProtocol {
                frame: "<non-utf8>".into(),
            })?;
        let mut lines = text.lines();
        let id_line = lines.next().ok_or_else(|| WorkspaceError::RemoteProtocol {
            frame: text.clone(),
        })?;
        let id = id_line
            .strip_prefix("COMMIT:")
            .ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?;
        let mut parents = Vec::new();
        let mut root = None;
        let mut author = None;
        let mut ts = None;
        for line in lines {
            if let Some(p) = line.strip_prefix("parents:") {
                parents = p
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| CommitId(s.to_string()))
                    .collect();
            } else if let Some(r) = line.strip_prefix("root:") {
                root = Some(ObjectId(r.to_string()));
            } else if let Some(a) = line.strip_prefix("author:") {
                author = Some(AuthorId(a.to_string()));
            } else if let Some(t) = line.strip_prefix("ts:") {
                ts = Some(t.parse().map_err(|_| WorkspaceError::RemoteProtocol {
                    frame: text.clone(),
                })?);
            }
        }
        Ok(WorkspaceCommit {
            id: CommitId(id.to_string()),
            parents,
            root_manifest_id: root.ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?,
            author: author.ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?,
            created_at_unix: ts.ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?,
        })
    }

    fn parse_object_frame(frame: &[u8]) -> Result<(String, Vec<u8>), WorkspaceError> {
        let text =
            String::from_utf8(frame.to_vec()).map_err(|_| WorkspaceError::RemoteProtocol {
                frame: "<non-utf8>".into(),
            })?;
        let rest =
            text.strip_prefix("OBJECT-DATA:")
                .ok_or_else(|| WorkspaceError::RemoteProtocol {
                    frame: text.clone(),
                })?;
        let (id, hex) = rest
            .split_once(':')
            .ok_or_else(|| WorkspaceError::RemoteProtocol {
                frame: text.clone(),
            })?;
        Ok((
            id.to_string(),
            unhex_bytes(hex).ok_or(WorkspaceError::RemoteProtocol { frame: text })?,
        ))
    }
}

/// Head 交换报告。
#[derive(Debug, Clone)]
pub struct HeadExchangeReport {
    pub local_heads: Vec<CommitId>,
    pub remote_heads: Vec<CommitId>,
}

/// 主动同步报告。
#[derive(Debug, Clone)]
pub struct SyncReport {
    pub remote_heads: Vec<CommitId>,
    pub fetched_commits: usize,
    pub fetched_objects: usize,
    pub disposition: MergeDisposition,
    pub common_ancestor: Option<CommitId>,
    pub conflict: Option<String>,
    pub merge_commit: Option<CommitId>,
}

/// 被动 serve 报告。
#[derive(Debug, Clone)]
pub struct SyncServedReport {
    pub served_commits: usize,
    pub served_objects: usize,
}

/// 字节转 hex（帧编码，无新依赖）。
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    s
}

fn unhex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for pair in chars.chunks(2) {
        let hi = pair[0].to_digit(16)?;
        let lo = pair[1].to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
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
        Workspace::init(
            WorkspaceId("ws-test".into()),
            InMemoryContentStore::new(),
            AuthorId("test-node".into()),
        )
        .expect("init ok")
    }

    fn genesis(ws: &Workspace<InMemoryContentStore>) -> CommitId {
        ws.heads().heads[0].clone()
    }

    #[test]
    fn init_creates_base_commit_and_single_head() {
        let ws = new_ws();
        assert_eq!(ws.heads().len(), 1);
        let base = genesis(&ws);
        assert_eq!(ws.heads().heads[0], base);
        let base_commit = ws.commit(&base).expect("base exists");
        assert!(base_commit.parents.is_empty());
    }

    #[test]
    fn offline_divergence_produces_two_heads() {
        let mut ws = new_ws();
        let base = genesis(&ws);
        let local = ws
            .commit_changes(&base, &[change("a.txt", b"local-a")])
            .expect("local commit ok");
        let remote = ws
            .commit_changes(&base, &[change("b.txt", b"remote-b")])
            .expect("remote commit ok");
        assert_ne!(local, base);
        assert_ne!(remote, base);
        assert_ne!(local, remote);
        assert_eq!(ws.heads().len(), 2);
    }

    #[test]
    fn commit_on_head_replaces_it() {
        let mut ws = new_ws();
        let base = genesis(&ws);
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
        let base = genesis(&ws);
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
        let base = genesis(&ws);
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
        let base = genesis(&ws);
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
        let base = genesis(&ws);
        let local = ws
            .commit_changes(&base, &[change("a.txt", b"local-a")])
            .expect("local ok");
        let remote = ws
            .commit_changes(&base, &[change("a.txt", b"remote-a")])
            .expect("remote ok");

        // v2：冲突落为持久化 ConflictObject，不再以 Err 返回。
        let report = ws.merge_heads(&local, &remote).expect("merge ok");
        assert_eq!(report.disposition, MergeDisposition::Diverged);
        assert!(report.merge_commit.is_none());
        let conflict_id = report.conflict.expect("conflict persisted");
        // 冲突不得改变 Head 集（保持两个分叉 Head，等待显式解决）。
        assert_eq!(ws.heads().len(), 2);

        // 冲突对象进 CAS 且可查。
        let conflict = ws.get_conflict(&conflict_id).expect("conflict indexed");
        assert_eq!(conflict.paths, vec!["a.txt".to_string()]);
        assert_eq!(conflict.base, base);
        assert!(matches!(conflict.state, ConflictState::Unresolved));
        assert!(
            ws.store()
                .contains(&conflict.cas_object_id)
                .expect("cas check")
        );

        // 显式解决（取本地）：产生双 parent Merge Commit，Heads 收敛。
        let merge = ws
            .resolve_conflict(
                &conflict_id,
                &[("a.txt".into(), ConflictResolution::TakeLocal)],
            )
            .expect("resolve ok");
        let merge_commit = ws.commit(&merge).expect("merge in dag");
        assert_eq!(merge_commit.parents.len(), 2);
        assert_eq!(ws.heads().len(), 1);
        assert_eq!(ws.heads().heads[0], merge);
        let resolved = ws.get_conflict(&conflict_id).expect("still indexed");
        assert!(matches!(resolved.state, ConflictState::Resolved { .. }));
        // 解决内容正确：取本地。
        assert_eq!(
            ws.read_from_head("a.txt").expect("read ok"),
            Some(b"local-a".to_vec())
        );
    }

    #[test]
    fn unknown_commit_is_rejected() {
        let mut ws = new_ws();
        let err = ws
            .commit_changes(&CommitId("deadbeefdeadbeef".into()), &[])
            .expect_err("must reject");
        assert_eq!(
            err,
            WorkspaceError::UnknownCommit {
                id: CommitId("deadbeefdeadbeef".into())
            }
        );
    }

    // ---------- 持久状态 / 写前日志 / 冷启动 reconcile ----------

    #[test]
    fn open_restores_durable_state_roundtrip() {
        let mut ws = new_ws();
        let c1 = ws
            .commit_changes(&genesis(&ws), &[change("a.txt", b"v1")])
            .expect("commit ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        let mut restored = Workspace::open(
            WorkspaceId("ws-test".into()),
            store,
            &root,
            AuthorId("test-node".into()),
        )
        .expect("open ok");
        assert_eq!(restored.heads().len(), 1);
        assert_eq!(restored.heads().heads[0], c1);
        // 恢复后可继续写入。
        let c2 = restored
            .commit_changes(&c1, &[change("b.txt", b"v2")])
            .expect("continue ok");
        assert_ne!(c2, c1);
    }

    #[test]
    fn journal_pending_then_commit_clears_marker() {
        let mut ws = new_ws();
        let pending = ws
            .journal_pending(&genesis(&ws), &[change("a.txt", b"v1")])
            .expect("pending ok");
        assert!(!pending.0.is_empty());
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
            .journal_pending(&genesis(&ws), &[change("a.txt", b"crash-a")])
            .expect("pending ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        // 冷启动：从持久状态恢复，回放日志 → redo 完成中断写入，不丢数据。
        let mut restored = Workspace::open(
            WorkspaceId("ws-test".into()),
            store,
            &root,
            AuthorId("test-node".into()),
        )
        .expect("open ok");
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
            .commit_changes(&genesis(&ws), &[change("a.txt", b"v1")])
            .expect("commit ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        let mut restored = Workspace::open(
            WorkspaceId("ws-test".into()),
            store,
            &root,
            AuthorId("test-node".into()),
        )
        .expect("open ok");
        // 提交已落 DAG（且 marker 已确认），回放无待处理 marker。
        let report = restored.reconcile_journal().expect("reconcile ok");
        assert_eq!(report.total, 0);
        assert_eq!(restored.heads().heads[0], c1);
    }
}

/// 远程提交会话阶段（MODULE.md 冻结契约：远程提交必须显式完成往返后才 Active）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRemotePhase {
    /// 正在发送 ChangeSet 帧、等待响应。
    Sending,
    /// 已收到 `OK:HEAD:<id>` 响应帧，往返完成。
    Active,
    /// 会话已关闭。
    Closed,
}

impl fmt::Display for WorkspaceRemotePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sending => write!(f, "Sending"),
            Self::Active => write!(f, "Active"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

/// 注入的远程帧通道（MODULE.md 冻结契约：避免 workspace -> transport 依赖边）。
///
/// 由组合根以 `transport::FrameStream` 适配装配（apps/nexus FrameStreamAdapter）。
pub trait WorkspaceTransport {
    /// 发送一帧。
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), WorkspaceError>;
    /// 接收一帧。
    fn recv_frame(&mut self) -> Result<Vec<u8>, WorkspaceError>;
}

/// 远程提交会话（PRODUCT §6）：在已认证帧通道上向提供方 Workspace 提交 ChangeSet，
/// 响应 `OK:HEAD:<commit_id>` 提取新 Head 后进入 Active；`REJECTED` 视为提供方拒绝。
#[derive(Debug, Clone)]
pub struct RemoteWorkspaceSession {
    phase: WorkspaceRemotePhase,
    head: Option<CommitId>,
}

impl RemoteWorkspaceSession {
    /// 发送 ChangeSet 帧并接收结果帧，完成一次远程提交往返。
    ///
    /// - `OK:HEAD:<commit_id>` -> Active，携带新 Head；
    /// - `REJECTED[:reason]` -> `WorkspaceError::RemoteRejected`（提供方拒绝）；
    /// - 其他帧 -> `WorkspaceError::RemoteProtocol`（协议不可识别，不得吞为成功）。
    pub fn commit(
        mut transport: Box<dyn WorkspaceTransport>,
        change_set: &[u8],
    ) -> Result<Self, WorkspaceError> {
        transport.send_frame(change_set)?;
        let frame = transport.recv_frame()?;
        let text = String::from_utf8(frame).map_err(|_| WorkspaceError::RemoteProtocol {
            frame: "<non-utf8>".into(),
        })?;
        if let Some(rest) = text.strip_prefix("OK:HEAD:") {
            let head = CommitId(rest.trim().to_string());
            if head.0.is_empty() {
                return Err(WorkspaceError::RemoteProtocol { frame: text });
            }
            Ok(Self {
                phase: WorkspaceRemotePhase::Active,
                head: Some(head),
            })
        } else if text.starts_with("REJECTED") {
            let reason = text
                .strip_prefix("REJECTED")
                .unwrap_or_default()
                .trim_start_matches(':')
                .trim()
                .to_string();
            Err(WorkspaceError::RemoteRejected { reason })
        } else {
            Err(WorkspaceError::RemoteProtocol { frame: text })
        }
    }

    /// 当前阶段。
    #[must_use]
    pub fn phase(&self) -> WorkspaceRemotePhase {
        self.phase.clone()
    }

    /// 提供方返回的新 Head（仅 Active 后有值）。
    #[must_use]
    pub fn head(&self) -> Option<&CommitId> {
        self.head.as_ref()
    }
}

#[cfg(test)]
mod remote_session_tests {
    use super::*;

    /// 测试用帧通道：预设响应帧。
    struct FakeTransport {
        rx: Vec<u8>,
    }

    impl WorkspaceTransport for FakeTransport {
        fn send_frame(&mut self, _payload: &[u8]) -> Result<(), WorkspaceError> {
            Ok(())
        }
        fn recv_frame(&mut self) -> Result<Vec<u8>, WorkspaceError> {
            Ok(self.rx.clone())
        }
    }

    #[test]
    fn commit_ok_extracts_new_head_and_activates() {
        let session = RemoteWorkspaceSession::commit(
            Box::new(FakeTransport {
                rx: b"OK:HEAD:C1".to_vec(),
            }),
            b"C0\nremote.txt\ncontent",
        )
        .expect("commit ok");
        assert_eq!(session.phase(), WorkspaceRemotePhase::Active);
        assert_eq!(session.head(), Some(&CommitId("C1".into())));
    }

    #[test]
    fn commit_rejected_maps_to_remote_rejected() {
        let err = RemoteWorkspaceSession::commit(
            Box::new(FakeTransport {
                rx: b"REJECTED:no such commit".to_vec(),
            }),
            b"UNKNOWN\nremote.txt\ncontent",
        )
        .expect_err("should be rejected");
        assert!(matches!(err, WorkspaceError::RemoteRejected { .. }));
    }

    #[test]
    fn commit_unknown_frame_maps_to_protocol_error() {
        let err = RemoteWorkspaceSession::commit(
            Box::new(FakeTransport {
                rx: b"garbage".to_vec(),
            }),
            b"C0\nremote.txt\ncontent",
        )
        .expect_err("should be protocol error");
        assert!(matches!(err, WorkspaceError::RemoteProtocol { .. }));
    }
}

#[cfg(test)]
mod access_provider_tests {
    use super::*;

    #[test]
    fn native_mount_wins_when_available() {
        let p = select_access_provider(true, false);
        assert_eq!(p, WorkspaceAccessProvider::NativeMountDirectory);
        assert_eq!(p.name(), "NativeMountDirectory");
    }

    #[test]
    fn materialization_fallback_without_mount() {
        // 场景 platform.workspace-projection-fallback 的路径。
        let p = select_access_provider(false, true);
        assert_eq!(p, WorkspaceAccessProvider::MaterializedDirectory);
        assert_eq!(p.name(), "MaterializedDirectory");
    }

    #[test]
    fn native_api_is_total_fallback() {
        let p = select_access_provider(false, false);
        assert_eq!(p, WorkspaceAccessProvider::NativeApi);
        assert_eq!(p.name(), "NativeApi");
    }

    #[test]
    fn selection_is_deterministic() {
        assert_eq!(
            select_access_provider(false, true),
            select_access_provider(false, true)
        );
    }
}

#[cfg(test)]
mod workspace_access_tests {
    use super::*;
    use nexus_storage::InMemoryContentStore;

    fn new_native_access() -> NativeApiWorkspaceAccess<InMemoryContentStore> {
        let ws = Workspace::init(
            WorkspaceId("ws-native-test".into()),
            InMemoryContentStore::new(),
            AuthorId("test-node".into()),
        )
        .expect("init ok");
        NativeApiWorkspaceAccess::new(ws)
    }

    #[test]
    fn native_api_write_then_read_without_commit() {
        let mut access = new_native_access();
        access.write_file("hello.txt", b"world").expect("write ok");
        // 不 commit，直接读 → 从 WorkingSet 读。
        let content = access.read_file("hello.txt").expect("read ok");
        assert_eq!(content, b"world".to_vec());
    }

    #[test]
    fn native_api_commit_persists_new_content() {
        let mut access = new_native_access();
        let base_head = access.head().cloned().expect("has head");
        access.write_file("a.txt", b"v1").expect("write ok");
        let new_head = access.commit().expect("commit ok");
        assert_ne!(new_head, base_head);
        // commit 后仍能读到。
        let content = access.read_file("a.txt").expect("read after commit");
        assert_eq!(content, b"v1".to_vec());
    }

    #[test]
    fn native_api_delete_removes_from_listing() {
        let mut access = new_native_access();
        access.write_file("keep.txt", b"keep").expect("write");
        access.write_file("drop.txt", b"drop").expect("write");
        access.commit().expect("commit");

        // 删除 drop.txt。
        access.delete("drop.txt").expect("delete");
        let entries = access.list_dir("").expect("list");
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(names.contains(&"keep.txt"));
        assert!(!names.contains(&"drop.txt"));
    }

    #[test]
    fn native_api_empty_commit_returns_current_head() {
        let mut access = new_native_access();
        let head_before = access.head().cloned().expect("has head");
        let head_after = access.commit().expect("empty commit");
        assert_eq!(head_before, head_after);
    }

    #[test]
    fn native_api_read_missing_returns_not_found() {
        let access = new_native_access();
        let err = access
            .read_file("nonexistent.txt")
            .expect_err("should fail");
        assert!(matches!(
            err,
            WorkspaceError::NotFound { path } if path == "nonexistent.txt"
        ));
    }

    #[test]
    fn native_api_delete_missing_returns_not_found() {
        let mut access = new_native_access();
        let err = access.delete("nonexistent.txt").expect_err("should fail");
        assert!(matches!(err, WorkspaceError::NotFound { .. }));
    }

    // ---------- MaterializedDirectoryAccess tests ----------

    fn temp_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nexus-ws-proj-test-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn new_materialized_access() -> (MaterializedDirectoryAccess<InMemoryContentStore>, PathBuf) {
        let store = InMemoryContentStore::new();
        let mut ws = Workspace::init(
            WorkspaceId("ws-mat-test".into()),
            store,
            AuthorId("test-node".into()),
        )
        .expect("init");
        let base = ws.heads().heads.first().cloned().expect("head");
        ws.commit_changes(
            &base,
            &[Change {
                path: "seed.txt".into(),
                content: b"seed-content".to_vec(),
            }],
        )
        .expect("seed commit");
        let dir = temp_dir("mat");
        let access =
            MaterializedDirectoryAccess::materialize(ws, dir.clone()).expect("materialize");
        (access, dir)
    }

    #[test]
    fn materialize_writes_files_to_dir() {
        let (access, dir) = new_materialized_access();
        let seed_file = dir.join("seed.txt");
        assert!(
            seed_file.exists(),
            "seed.txt should exist in materialized dir"
        );
        let content = std::fs::read(&seed_file).expect("read seed");
        assert_eq!(content, b"seed-content".to_vec());
        let _ = access; // keep alive
    }

    #[test]
    fn materialized_write_commit_advances_head() {
        let (mut access, dir) = new_materialized_access();
        let base_head = access.head().cloned().expect("head");

        // 写新文件到目录。
        access.write_file("new.txt", b"new-content").expect("write");
        let new_head = access.commit().expect("commit");
        assert_ne!(new_head, base_head);

        // 从 Workspace 读回验证。
        let content = access.read_file("new.txt").expect("read committed");
        assert_eq!(content, b"new-content".to_vec());
        let _ = dir;
    }

    #[test]
    fn materialized_delete_commit_removes_from_workspace() {
        let (mut access, dir) = new_materialized_access();
        // 删除物化目录中的 seed.txt。
        access.delete("seed.txt").expect("delete");
        access.commit().expect("commit");

        // 验证 Workspace 中 seed.txt 已不存在。
        let err = access.read_file("seed.txt").expect_err("should be gone");
        assert!(matches!(err, WorkspaceError::NotFound { .. }));
        let _ = dir;
    }

    #[test]
    fn materialized_read_missing_returns_not_found() {
        let (access, dir) = new_materialized_access();
        let err = access
            .read_file("nonexistent.txt")
            .expect_err("should fail");
        assert!(matches!(err, WorkspaceError::NotFound { .. }));
        let _ = dir;
    }

    #[test]
    fn materialized_path_traversal_is_rejected() {
        let (mut access, dir) = new_materialized_access();
        // 尝试越界写。
        let err = access
            .write_file("../escape.txt", b"bad")
            .expect_err("traversal should fail");
        assert!(matches!(err, WorkspaceError::PathTraversal { .. }));
        // 尝试越界读。
        let err = access
            .read_file("../escape.txt")
            .expect_err("traversal should fail");
        assert!(matches!(err, WorkspaceError::PathTraversal { .. }));
        // 尝试越界删。
        let err = access
            .delete("../escape.txt")
            .expect_err("traversal should fail");
        assert!(matches!(err, WorkspaceError::PathTraversal { .. }));
        let _ = dir;
    }

    #[test]
    fn materialized_single_level_listing() {
        let (mut access, dir) = new_materialized_access();
        // 创建子目录。
        access
            .write_file("subdir/child.txt", b"child")
            .expect("write");
        let entries = access.list_dir("").expect("list root");
        // 根级别应该有 seed.txt 和 subdir（目录）。
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(names.contains(&"seed.txt"));
        assert!(names.contains(&"subdir"));
        // subdir 应该被标记为目录。
        let subdir_entry = entries
            .iter()
            .find(|e| e.path == "subdir")
            .expect("subdir entry");
        assert!(subdir_entry.is_dir);
        let _ = dir;
    }
}
