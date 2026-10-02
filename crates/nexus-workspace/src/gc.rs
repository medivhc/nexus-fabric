//! Workspace 存储治理（v9 §20）：Reachability GC 两阶段回收、Shallow/Sparse
//! Replica、On-demand Deepening、Storage Quota、Pack/Compaction、后台 GC 调度。
//!
//! 不变量（MODULE.md，AGENTS.md §25 Stop Conditions）：
//!
//! - GC 只能删除不再被 protected roots 可达、且已过安全保留期的对象；
//! - 任何情况下不删除仍可达或未合并的数据；
//! - 删除走两阶段：先 `plan_gc` 生成候选 → `apply_tombstones` 生成
//!   Tombstone/Deletion Intent（持久化）→ `sweep` 在保留期后物理删除；
//! - `sweep` 前重验可达性：tombstone 期间复活的对象撤销 tombstone，不删除；
//! - in-flight fetch / active pin / recovery journal 阻止删除。

use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use nexus_storage::{ContentStore, ObjectId, ReachabilityGc, StorageStats};

use super::{
    CommitId, HeadSet, Manifest, Workspace, WorkspaceCommit, WorkspaceError, WorkspaceId, seq_of,
};

/// 默认安全保留期：14 天（v9 §20 移动端默认值；桌面/服务端可配更长）。
pub const DEFAULT_RETENTION_SECS: u64 = 14 * 24 * 3600;

/// 默认单次 sweep 上限（限速，避免长暂停）。
pub const DEFAULT_MAX_SWEEP_PER_RUN: u64 = 10_000;

/// 默认 GC 调度间隔。
pub const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 存储配额策略（v9 §20）。
#[derive(Debug, Clone)]
pub struct QuotaPolicy {
    /// soft 上限：超过 → 触发后台 GC。
    pub soft_bytes: u64,
    /// hard 上限：超过 → 主动驱逐 / shallowing / 预取暂停（经 `QuotaHandler`）。
    pub hard_bytes: u64,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            soft_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
            hard_bytes: 20 * 1024 * 1024 * 1024, // 20 GiB
        }
    }
}

/// 配额压力等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaPressure {
    None,
    Soft,
    Hard,
}

impl QuotaPolicy {
    /// 压力判定（边界取高等级：== hard 按 Hard 算）。
    #[must_use]
    pub fn pressure(&self, usage_bytes: u64) -> QuotaPressure {
        if usage_bytes >= self.hard_bytes {
            QuotaPressure::Hard
        } else if usage_bytes >= self.soft_bytes {
            QuotaPressure::Soft
        } else {
            QuotaPressure::None
        }
    }
}

/// GC 运行配置。
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// 安全保留期（秒）：tombstone 满此期限后才可物理删除。
    pub retention_secs: u64,
    /// 单次 sweep 删除上限（限速）。
    pub max_sweep_per_run: u64,
    /// 配额策略。
    pub quota: QuotaPolicy,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            retention_secs: DEFAULT_RETENTION_SECS,
            max_sweep_per_run: DEFAULT_MAX_SWEEP_PER_RUN,
            quota: QuotaPolicy::default(),
        }
    }
}

/// GC Protected Roots（v9 §20）。
#[derive(Debug, Clone, Default)]
pub struct GcRoots {
    /// 受保护提交：当前 Heads + 显式保留 Snapshot + 未合并分支 + Conflict 相关提交。
    pub commits: Vec<CommitId>,
    /// Active pin（内存态，进程持有；crash 后消失——语义正确）。
    pub pinned_objects: Vec<ObjectId>,
    /// Legal / user hold（持久态，显式释放前不得删除）。
    pub holds: Vec<ObjectId>,
}

/// 回收原因（可诊断，非自由文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcReason {
    /// 不再被 protected roots 可达。
    Unreachable,
    /// 被更新的 durable state 对象取代。
    SupersededState,
}

impl GcReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GcReason::Unreachable => "unreachable",
            GcReason::SupersededState => "superseded-state",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "unreachable" => Some(GcReason::Unreachable),
            "superseded-state" => Some(GcReason::SupersededState),
            _ => None,
        }
    }
}

/// Tombstone / Deletion Intent（v9 §20）：先生成（持久化），后按保留期物理删除。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    pub object_id: ObjectId,
    pub tombstoned_at_unix: u64,
    pub reason: GcReason,
}

/// 一次 GC 规划的结果：可达集 + 待 tombstone 的候选（本阶段不删除任何东西）。
#[derive(Debug, Clone)]
pub struct GcPlan {
    pub reachable: HashSet<ObjectId>,
    pub candidates: Vec<(ObjectId, GcReason)>,
    pub planned_at_unix: u64,
}

/// 一次完整 GC 的结构化报告。
#[derive(Debug, Clone)]
pub struct GcReport {
    pub reachable_count: u64,
    pub tombstoned: u64,
    pub swept: u64,
    pub blocked_by_pin: u64,
    pub blocked_by_inflight: u64,
    pub resurrected: u64,
    pub quota_pressure: QuotaPressure,
}

/// 正在 fetch 的对象集合：sweep 必须跳过（v9 §20）。
#[derive(Debug, Default)]
pub struct InFlightSet {
    fetching: HashSet<ObjectId>,
}

impl InFlightSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: ObjectId) {
        self.fetching.insert(id);
    }

    pub fn remove(&mut self, id: &ObjectId) {
        self.fetching.remove(id);
    }

    #[must_use]
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.fetching.contains(id)
    }

    /// RAII guard：drop 时自动移出集合。
    pub fn guard(&mut self, id: ObjectId) -> InFlightGuard<'_> {
        self.fetching.insert(id.clone());
        InFlightGuard { set: self, id }
    }
}

/// `InFlightSet::guard` 的 RAII 守卫。
pub struct InFlightGuard<'a> {
    set: &'a mut InFlightSet,
    id: ObjectId,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.set.remove(&self.id);
    }
}

/// Replica 策略（v9 §20）：本地副本持有策略，不改变全局 DAG 的逻辑历史。
#[derive(Debug, Clone, Default)]
pub struct ReplicaPolicy {
    /// Shallow：只同步最近 N 代（None = 全量）。
    pub max_depth: Option<u32>,
    /// Sparse：只持有这些路径前缀的对象（空 = 全量）。
    pub sparse_paths: Vec<String>,
}

impl ReplicaPolicy {
    /// 该路径的对象是否在 sparse 策略内。
    #[must_use]
    pub fn path_wanted(&self, path: &str) -> bool {
        self.sparse_paths.is_empty()
            || self
                .sparse_paths
                .iter()
                .any(|p| path.starts_with(p.as_str()))
    }
}

/// 远端对象/提交拉取（Composition Root 适配传输实现；portable-core 只定义形状）。
pub trait ObjectFetcher {
    fn fetch_object(&mut self, id: &ObjectId) -> Result<Vec<u8>, WorkspaceError>;
    fn fetch_commit(&mut self, id: &CommitId) -> Result<WorkspaceCommit, WorkspaceError>;
}

/// 定点读取的三态结果：shallow/sparse 下"本地没有"是预期状态，不是损坏。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Found(Vec<u8>),
    /// 路径不在该提交的 Manifest 中。
    NotInManifest,
    /// 在 Manifest 中，但本地 Replica 未持有（可 `deepen` 拉取）。
    NotHeldLocally(ObjectId),
}

/// On-demand deepening 报告。
#[derive(Debug, Clone)]
pub struct DeepenReport {
    pub commits_fetched: u64,
    pub objects_fetched: u64,
}

/// Shallow clone 报告。
#[derive(Debug, Clone)]
pub struct ShallowReport {
    pub commits_imported: u64,
    pub objects_fetched: u64,
    /// 未持有的父提交（ancestry frontier，v9 §20）。
    pub frontier: Vec<CommitId>,
}

/// Pack / Metadata Compaction 报告（v9 §20）：不改变 CommitId 语义。
#[derive(Debug, Clone)]
pub struct PackReport {
    /// 已失效的 tombstone 记录被清理条数（目标对象已不存在）。
    pub tombstone_records_purged: u64,
    pub state_rewritten: bool,
    pub objects_before: u64,
    pub objects_after: u64,
}

/// GC 运行门控（移动端可接"仅 WiFi/充电"策略；默认恒真）。
pub trait GcRunPolicy: Send + Sync {
    fn can_run_now(&self) -> bool;
}

/// 恒真门控。
#[derive(Debug, Default)]
pub struct AlwaysRun;

impl GcRunPolicy for AlwaysRun {
    fn can_run_now(&self) -> bool {
        true
    }
}

/// Hard 配额压力处理器（W2 Prefetch 暂停 / W4 Cache 驱逐的扩展点）。
pub trait QuotaHandler: Send + Sync {
    fn on_hard_pressure(&self, usage_bytes: u64);
}

/// 空实现。
#[derive(Debug, Default)]
pub struct NoopQuotaHandler;

impl QuotaHandler for NoopQuotaHandler {
    fn on_hard_pressure(&self, _usage_bytes: u64) {}
}

/// 后台 GC 调度器配置。
#[derive(Debug, Clone)]
pub struct GcSchedulerConfig {
    pub gc: GcConfig,
    pub interval_secs: u64,
}

impl Default for GcSchedulerConfig {
    fn default() -> Self {
        Self {
            gc: GcConfig::default(),
            interval_secs: DEFAULT_GC_INTERVAL_SECS,
        }
    }
}

/// 后台 GC 调度器（§15 Structured Concurrency：Owner + 可取消 + 回收语义）。
///
/// - D1=A：soft limit 触发后台 GC，hard pressure 经 `QuotaHandler` 触发驱逐；
///   GC 永不在 commit 热路径上运行。
pub struct GcScheduler {
    handle: Mutex<Option<GcHandle>>,
}

/// 调度器句柄（`shutdown` 幂等，等待线程退出）。
pub struct GcHandle {
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl GcScheduler {
    /// 启动后台 GC 线程（std thread + AtomicBool，无 tokio 依赖，portable-core）。
    pub fn spawn<S>(
        ws: Arc<Mutex<Workspace<S>>>,
        config: GcSchedulerConfig,
        policy: Box<dyn GcRunPolicy>,
        quota_handler: Box<dyn QuotaHandler>,
    ) -> Arc<Self>
    where
        S: ContentStore + ReachabilityGc + StorageStats + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let paused2 = Arc::clone(&paused);
        let thread = thread::spawn(move || {
            Self::run_loop(ws, config, policy, quota_handler, stop2, paused2);
        });
        Arc::new(Self {
            handle: Mutex::new(Some(GcHandle {
                stop,
                paused,
                thread: Some(thread),
            })),
        })
    }

    fn run_loop<S>(
        ws: Arc<Mutex<Workspace<S>>>,
        config: GcSchedulerConfig,
        policy: Box<dyn GcRunPolicy>,
        quota_handler: Box<dyn QuotaHandler>,
        stop: Arc<AtomicBool>,
        paused: Arc<AtomicBool>,
    ) where
        S: ContentStore + ReachabilityGc + StorageStats + Send + 'static,
    {
        let interval = config.interval_secs.max(1);
        let mut elapsed = 0u64;
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
            if stop.load(Ordering::Relaxed) {
                return;
            }
            elapsed += 1;
            if elapsed < interval {
                continue;
            }
            elapsed = 0;
            if paused.load(Ordering::Relaxed) || !policy.can_run_now() {
                continue;
            }
            let mut guard = match ws.lock() {
                Ok(g) => g,
                Err(_) => return, // poisoned：退出，不 panic
            };
            let usage = match guard.store_usage() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let pressure = config.gc.quota.pressure(usage);
            match pressure {
                QuotaPressure::None => {}
                QuotaPressure::Soft | QuotaPressure::Hard => {
                    if pressure == QuotaPressure::Hard {
                        quota_handler.on_hard_pressure(usage);
                    }
                    let inflight = InFlightSet::new();
                    // 后台任务失败不 panic：下次 tick 重试。
                    let _ = guard.run_gc(&config.gc, &inflight);
                }
            }
        }
    }

    fn with_handle(&self, f: impl FnOnce(&GcHandle)) {
        if let Ok(guard) = self.handle.lock() {
            if let Some(h) = guard.as_ref() {
                f(h);
            }
        }
    }

    /// 暂停后台 GC（幂等）。
    pub fn pause(&self) {
        self.with_handle(|h| h.paused.store(true, Ordering::Relaxed));
    }

    /// 恢复后台 GC（幂等）。
    pub fn resume(&self) {
        self.with_handle(|h| h.paused.store(false, Ordering::Relaxed));
    }

    /// 停止并回收线程（幂等；Owner 语义）。
    pub fn shutdown(&self) {
        let handle = self.handle.lock().ok().and_then(|mut g| g.take());
        if let Some(mut h) = handle {
            h.stop.store(true, Ordering::Relaxed);
            if let Some(t) = h.thread.take() {
                let _ = t.join();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace 方法：pin / hold / retain / replica policy
// ---------------------------------------------------------------------------

impl<S: ContentStore> Workspace<S> {
    /// Active pin：进程持有该对象，GC 永不删除（内存态，crash 后消失——语义正确）。
    pub fn pin(&mut self, id: ObjectId) {
        self.pins.insert(id);
    }

    /// 解除 pin。
    pub fn unpin(&mut self, id: &ObjectId) {
        self.pins.remove(id);
    }

    #[must_use]
    pub fn is_pinned(&self, id: &ObjectId) -> bool {
        self.pins.contains(id)
    }

    /// Legal / user hold：持久态，显式释放前 GC 不得删除。
    pub fn hold(&mut self, id: ObjectId) -> Result<(), WorkspaceError> {
        if !self.holds.contains(&id) {
            self.holds.push(id);
            self.persist_state()?;
        }
        Ok(())
    }

    /// 释放 hold。
    pub fn release_hold(&mut self, id: &ObjectId) -> Result<(), WorkspaceError> {
        let before = self.holds.len();
        self.holds.retain(|h| h != id);
        if self.holds.len() != before {
            self.persist_state()?;
        }
        Ok(())
    }

    /// 显式保留 Snapshot：成为 GC Protected Root（持久态）。
    pub fn retain_snapshot(&mut self, id: CommitId) -> Result<(), WorkspaceError> {
        if self.commits.contains_key(&id) && !self.retained.contains(&id) {
            self.retained.push(id);
            self.persist_state()?;
        }
        Ok(())
    }

    /// 解除保留。
    pub fn release_snapshot(&mut self, id: &CommitId) -> Result<(), WorkspaceError> {
        let before = self.retained.len();
        self.retained.retain(|r| r != id);
        if self.retained.len() != before {
            self.persist_state()?;
        }
        Ok(())
    }

    /// 设置本地 Replica 策略（shallow/sparse，不改变全局 DAG 逻辑历史）。
    pub fn set_replica_policy(&mut self, policy: ReplicaPolicy) {
        self.replica_policy = policy;
    }

    #[must_use]
    pub fn replica_policy(&self) -> &ReplicaPolicy {
        &self.replica_policy
    }

    /// 供 `ObjectFetcher` 实现用的对象导出（shallow/sync 的读侧）。
    pub fn export_object(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, WorkspaceError> {
        self.store
            .get(id)
            .map_err(|reason| WorkspaceError::StoreFailure { reason })
    }

    /// 定点读取（shallow/sparse 友好）：本地未持有返回 `NotHeldLocally`，
    /// 是预期状态，不是损坏——调用方可据此 `deepen`。
    pub fn read_at_commit(&self, id: &CommitId, path: &str) -> Result<ReadOutcome, WorkspaceError> {
        let commit = self
            .commits
            .get(id)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: id.clone() })?;
        let manifest = self.load_manifest(&commit.root_manifest_id)?;
        match manifest.get(path) {
            None => Ok(ReadOutcome::NotInManifest),
            Some(oid) => match self
                .store
                .get(oid)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            {
                Some(bytes) => Ok(ReadOutcome::Found(bytes)),
                None => Ok(ReadOutcome::NotHeldLocally(oid.clone())),
            },
        }
    }

    /// 空 Workspace（shallow clone / sync 导入的起点；调用方负责 `import_commits`）。
    pub fn empty(id: WorkspaceId, store: S) -> Self {
        Self {
            id,
            commits: HashMap::new(),
            heads: HeadSet::default(),
            store,
            next_seq: 1,
            state_root: ObjectId(String::new()),
            journal: Vec::new(),
            tombstones: Vec::new(),
            retained: Vec::new(),
            holds: Vec::new(),
            pins: HashSet::new(),
            replica_policy: ReplicaPolicy::default(),
            shallow_frontier: Vec::new(),
        }
    }

    /// 导入已提交（导入方保证其真实性；传输层认证在 Composition Root 完成）。
    ///
    /// parents 缺失的提交记入 `shallow_frontier`（v9 §20 ancestry frontier）。
    /// 同 id 已存在时必须字节一致，否则报 `CorruptState`（不静默覆盖）。
    pub fn import_commits(
        &mut self,
        commits: Vec<WorkspaceCommit>,
        heads: Vec<CommitId>,
    ) -> Result<(), WorkspaceError> {
        let ids: HashSet<&CommitId> = commits.iter().map(|c| &c.id).collect();
        for c in &commits {
            for p in &c.parents {
                if !self.commits.contains_key(p)
                    && !ids.contains(p)
                    && !self.shallow_frontier.contains(p)
                {
                    self.shallow_frontier.push(p.clone());
                }
            }
        }
        for c in commits {
            if let Some(existing) = self.commits.get(&c.id) {
                if existing != &c {
                    return Err(WorkspaceError::CorruptState {
                        reason: format!("commit id conflict on import: {}", c.id.0),
                    });
                }
                continue;
            }
            self.next_seq = self.next_seq.max(seq_of(&c.id).map(|s| s + 1).unwrap_or(1));
            self.commits.insert(c.id.clone(), c);
        }
        for h in heads {
            if !self.commits.contains_key(&h) {
                return Err(WorkspaceError::UnknownCommit { id: h });
            }
            self.heads.add(h);
        }
        self.persist_state()?;
        Ok(())
    }

    /// 未持有的父提交（shallow frontier）。
    #[must_use]
    pub fn shallow_frontier(&self) -> &[CommitId] {
        &self.shallow_frontier
    }

    /// Pack / Metadata Compaction：清理目标已不存在的 tombstone 记录并重写
    /// state（不改变任何 CommitId 语义；旧 state 对象进入正常 GC 流程）。
    pub fn compact(&mut self) -> Result<PackReport, WorkspaceError> {
        let objects_before = self
            .store
            .object_ids()
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            .len() as u64;
        let mut purged = 0u64;
        let tombstones = std::mem::take(&mut self.tombstones);
        for ts in tombstones {
            let gone = !self
                .store
                .contains(&ts.object_id)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
            if gone {
                purged += 1;
            } else {
                self.tombstones.push(ts);
            }
        }
        self.persist_state()?;
        let objects_after = self
            .store
            .object_ids()
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            .len() as u64;
        Ok(PackReport {
            tombstone_records_purged: purged,
            state_rewritten: true,
            objects_before,
            objects_after,
        })
    }
}

// ---------------------------------------------------------------------------
// Workspace 方法：Reachability GC 两阶段（需存储层 GC 原语）
// ---------------------------------------------------------------------------

impl<S: ContentStore + ReachabilityGc + StorageStats> Workspace<S> {
    /// 当前 GC Protected Roots（v9 §20）。
    #[must_use]
    pub fn gc_roots(&self) -> GcRoots {
        let mut commits = self.heads.heads.clone();
        commits.extend(self.retained.iter().cloned());
        commits.extend(self.conflict_commits());
        GcRoots {
            commits,
            pinned_objects: self.pins.iter().cloned().collect(),
            holds: self.holds.clone(),
        }
    }

    /// W3 扩展点：持久化 Conflict Object 及其 Base/Local/Remote 提交。
    /// 当前切片无持久化冲突对象，返回空（W3 填入）。
    fn conflict_commits(&self) -> Vec<CommitId> {
        Vec::new()
    }

    /// 可达闭包：protected commits 传递闭包 → manifest → 内容对象，
    /// 外加 journal pending 的 manifest、当前 state_root、pin/hold。
    fn compute_reachable(&self, roots: &GcRoots) -> Result<HashSet<ObjectId>, WorkspaceError> {
        let mut reachable = HashSet::new();
        // state_root 自身永不删除（冷启动恢复依赖它）。
        if !self.state_root.0.is_empty() {
            reachable.insert(self.state_root.clone());
        }
        let mut stack: Vec<CommitId> = roots.commits.clone();
        // journal 中的 pending 提交：manifest 已落盘但未进 DAG，同样保护
        //（pending write-back，v9 §20）。
        for e in &self.journal {
            stack.push(e.commit_id.clone());
        }
        let mut visited: HashSet<CommitId> = HashSet::new();
        while let Some(cid) = stack.pop() {
            if !visited.insert(cid.clone()) {
                continue;
            }
            // shallow frontier：本地没有该提交则跳过（不报错）。
            let Some(commit) = self.commits.get(&cid) else {
                continue;
            };
            reachable.insert(commit.root_manifest_id.clone());
            let manifest = self.load_manifest(&commit.root_manifest_id)?;
            for (_, oid) in manifest.entries.iter() {
                reachable.insert(oid.clone());
            }
            stack.extend(commit.parents.iter().cloned());
        }
        // journal manifest 的内容对象（与提交闭包分开处理，因为 pending 提交不在 commits 中）。
        for e in &self.journal {
            reachable.insert(e.root_manifest_id.clone());
            let manifest = self.load_manifest(&e.root_manifest_id)?;
            for (_, oid) in manifest.entries.iter() {
                reachable.insert(oid.clone());
            }
        }
        reachable.extend(roots.pinned_objects.iter().cloned());
        reachable.extend(roots.holds.iter().cloned());
        Ok(reachable)
    }

    /// Phase 1：规划。计算可达集，枚举 tombstone 候选（本阶段不删除任何东西）。
    pub fn plan_gc(&self, config: &GcConfig) -> Result<GcPlan, WorkspaceError> {
        let _ = config;
        let roots = self.gc_roots();
        let reachable = self.compute_reachable(&roots)?;
        let tombstoned: HashSet<ObjectId> = self
            .tombstones
            .iter()
            .map(|t| t.object_id.clone())
            .collect();
        let mut candidates = Vec::new();
        for oid in self
            .store
            .object_ids()
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
        {
            if reachable.contains(&oid) || tombstoned.contains(&oid) {
                continue;
            }
            // 被取代的旧 state 对象单独标记原因（只影响可诊断性，不影响正确性）。
            let reason = if self.is_superseded_state(&oid) {
                GcReason::SupersededState
            } else {
                GcReason::Unreachable
            };
            candidates.push((oid, reason));
        }
        candidates.sort_by(|a, b| a.0.0.cmp(&b.0.0));
        Ok(GcPlan {
            reachable,
            candidates,
            planned_at_unix: now_unix(),
        })
    }

    /// 旧 state 对象判定：能解析为 state 文本但不是当前 state_root。
    fn is_superseded_state(&self, oid: &ObjectId) -> bool {
        if oid == &self.state_root || self.state_root.0.is_empty() {
            return false;
        }
        self.store
            .get(oid)
            .ok()
            .flatten()
            .map(|b| b.starts_with(b"nexus-workspace-state"))
            .unwrap_or(false)
    }

    /// Phase 2a：生成 Tombstone/Deletion Intent（持久化，不删除）。
    /// 返回新生成的 tombstone 数。
    pub fn apply_tombstones(&mut self, plan: &GcPlan) -> Result<u64, WorkspaceError> {
        let mut n = 0u64;
        for (oid, reason) in &plan.candidates {
            if self.tombstones.iter().any(|t| &t.object_id == oid) {
                continue;
            }
            self.tombstones.push(Tombstone {
                object_id: oid.clone(),
                tombstoned_at_unix: plan.planned_at_unix,
                reason: *reason,
            });
            n += 1;
        }
        if n > 0 {
            self.persist_state()?;
        }
        Ok(n)
    }

    /// Phase 2b：物理删除已过保留期的 tombstone（Stop Condition：删除前重验可达性）。
    ///
    /// - tombstone 期间复活（又可达）→ 撤销 tombstone，不删除；
    /// - pin/hold/in-flight → 保留 tombstone，计数 blocked；
    /// - 未过保留期 / 超限速 → 保留，留待下次。
    pub fn sweep(
        &mut self,
        config: &GcConfig,
        inflight: &InFlightSet,
    ) -> Result<GcReport, WorkspaceError> {
        let now = now_unix();
        let roots = self.gc_roots();
        let reachable = self.compute_reachable(&roots)?;
        let reachable_count = reachable.len() as u64;
        let mut swept = 0u64;
        let mut blocked_by_pin = 0u64;
        let mut blocked_by_inflight = 0u64;
        let mut resurrected = 0u64;
        let mut kept = Vec::new();
        for ts in std::mem::take(&mut self.tombstones) {
            if reachable.contains(&ts.object_id) {
                resurrected += 1;
                continue;
            }
            if roots.pinned_objects.contains(&ts.object_id) || roots.holds.contains(&ts.object_id) {
                blocked_by_pin += 1;
                kept.push(ts);
                continue;
            }
            if inflight.contains(&ts.object_id) {
                blocked_by_inflight += 1;
                kept.push(ts);
                continue;
            }
            if now.saturating_sub(ts.tombstoned_at_unix) < config.retention_secs {
                kept.push(ts);
                continue;
            }
            if swept >= config.max_sweep_per_run {
                kept.push(ts);
                continue;
            }
            if self
                .store
                .delete_object(&ts.object_id)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            {
                swept += 1;
            }
            // 目标已不存在：tombstone 记录自然失效，不保留。
        }
        self.tombstones = kept;
        self.persist_state()?;
        let quota_pressure = config
            .quota
            .pressure(self.store_usage().unwrap_or(u64::MAX));
        Ok(GcReport {
            reachable_count,
            tombstoned: 0,
            swept,
            blocked_by_pin,
            blocked_by_inflight,
            resurrected,
            quota_pressure,
        })
    }

    /// 一次完整 GC：plan → tombstone → sweep。
    pub fn run_gc(
        &mut self,
        config: &GcConfig,
        inflight: &InFlightSet,
    ) -> Result<GcReport, WorkspaceError> {
        let plan = self.plan_gc(config)?;
        let tombstoned = self.apply_tombstones(&plan)?;
        let mut report = self.sweep(config, inflight)?;
        report.tombstoned = tombstoned;
        Ok(report)
    }

    /// 当前存储用量（配额判定）。
    pub fn store_usage(&self) -> Result<u64, WorkspaceError> {
        self.store
            .usage_bytes()
            .map_err(|reason| WorkspaceError::StoreFailure { reason })
    }

    /// 当前配额压力。
    pub fn quota_pressure(&self, config: &GcConfig) -> Result<QuotaPressure, WorkspaceError> {
        Ok(config.quota.pressure(self.store_usage()?))
    }

    /// Shallow clone：只取 head 回溯 `max_depth` 代的提交 + 对象（v9 §20）。
    ///
    /// 内容寻址校验：fetch 回来的字节必须对上请求 id，否则 `CorruptState`。
    /// 拉取按老→新顺序，保证 parents 先入库（frontier 计算正确）。
    pub fn shallow_clone(
        id: WorkspaceId,
        store: S,
        head: &CommitId,
        policy: &ReplicaPolicy,
        fetcher: &mut dyn ObjectFetcher,
    ) -> Result<(Self, ShallowReport), WorkspaceError> {
        let depth = policy.max_depth.unwrap_or(u32::MAX);
        let mut chain: Vec<WorkspaceCommit> = Vec::new();
        let mut cur = Some(head.clone());
        while let Some(cid) = cur {
            if chain.len() as u32 >= depth {
                break;
            }
            let commit = fetcher.fetch_commit(&cid)?;
            if commit.id != cid {
                return Err(WorkspaceError::CorruptState {
                    reason: format!("fetch_commit id mismatch: {}", cid.0),
                });
            }
            cur = commit.parents.first().cloned();
            chain.push(commit);
        }
        if chain.is_empty() {
            return Err(WorkspaceError::UnknownCommit { id: head.clone() });
        }
        let mut ws = Self::empty(id, store);
        ws.set_replica_policy(policy.clone());
        let mut objects_fetched = 0u64;
        for commit in chain.iter().rev() {
            objects_fetched += ws.fetch_commit_objects(commit, policy, fetcher)?;
        }
        let n = chain.len() as u64;
        let heads = vec![head.clone()];
        ws.import_commits(chain, heads)?;
        let frontier = ws.shallow_frontier.clone();
        Ok((
            ws,
            ShallowReport {
                commits_imported: n,
                objects_fetched,
                frontier,
            },
        ))
    }

    /// 拉取一个提交的 manifest + 文件对象（sparse 过滤 + 内容寻址校验）。
    /// 返回新拉取的对象数。
    fn fetch_commit_objects(
        &mut self,
        commit: &WorkspaceCommit,
        policy: &ReplicaPolicy,
        fetcher: &mut dyn ObjectFetcher,
    ) -> Result<u64, WorkspaceError> {
        let mut fetched = 0u64;
        let mbytes = fetcher.fetch_object(&commit.root_manifest_id)?;
        let manifest = Manifest::from_bytes(&commit.root_manifest_id, &mbytes)?;
        let mid = self
            .store
            .put(&mbytes)
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        debug_assert_eq!(mid, commit.root_manifest_id);
        for (path, oid) in manifest.entries.iter() {
            if !policy.path_wanted(path) {
                continue;
            }
            if self
                .store
                .contains(oid)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            {
                continue;
            }
            let bytes = fetcher.fetch_object(oid)?;
            let got = self
                .store
                .put(&bytes)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
            if &got != oid {
                return Err(WorkspaceError::CorruptState {
                    reason: format!("fetched object id mismatch for {path}"),
                });
            }
            fetched += 1;
        }
        Ok(fetched)
    }

    /// On-demand deepening：把 `target` 的缺失祖先按需拉取（v9 §20）。
    /// 不改变任何 CommitId；frontier 随之收缩。
    pub fn deepen(
        &mut self,
        target: &CommitId,
        fetcher: &mut dyn ObjectFetcher,
    ) -> Result<DeepenReport, WorkspaceError> {
        let mut missing: Vec<WorkspaceCommit> = Vec::new();
        let mut cur = Some(target.clone());
        let mut visited = HashSet::new();
        while let Some(cid) = cur {
            if !visited.insert(cid.clone()) {
                break;
            }
            if self.commits.contains_key(&cid) {
                break;
            }
            let commit = fetcher.fetch_commit(&cid)?;
            if commit.id != cid {
                return Err(WorkspaceError::CorruptState {
                    reason: format!("fetch_commit id mismatch: {}", cid.0),
                });
            }
            cur = commit.parents.first().cloned();
            missing.push(commit);
        }
        let mut commits_fetched = 0u64;
        let mut objects_fetched = 0u64;
        // 老 → 新，保证 parents 先入库。
        for commit in missing.iter().rev() {
            objects_fetched +=
                self.fetch_commit_objects(commit, &self.replica_policy.clone(), fetcher)?;
            commits_fetched += 1;
        }
        let ordered: Vec<WorkspaceCommit> = missing.into_iter().rev().collect();
        self.import_commits(ordered, Vec::new())?;
        self.shallow_frontier
            .retain(|f| !self.commits.contains_key(f));
        self.persist_state()?;
        Ok(DeepenReport {
            commits_fetched,
            objects_fetched,
        })
    }
}

#[cfg(test)]
mod gc_tests {
    use super::*;
    use nexus_storage::InMemoryContentStore;

    fn test_config() -> GcConfig {
        GcConfig {
            retention_secs: 0,
            max_sweep_per_run: 100_000,
            quota: QuotaPolicy::default(),
        }
    }

    fn ws_with_commits() -> Workspace<InMemoryContentStore> {
        let mut ws = Workspace::init(
            WorkspaceId("ws-gc-test".into()),
            InMemoryContentStore::new(),
        )
        .expect("init ok");
        let base = ws.heads().heads[0].clone();
        let c1 = ws
            .commit_changes(
                &base,
                &[super::super::Change {
                    path: "a.txt".into(),
                    content: b"aaa".to_vec(),
                }],
            )
            .expect("commit ok");
        ws.commit_changes(
            &c1,
            &[super::super::Change {
                path: "b.txt".into(),
                content: b"bbb".to_vec(),
            }],
        )
        .expect("commit ok");
        ws
    }

    #[test]
    fn retention_protects_recent_tombstones() {
        let mut ws = ws_with_commits();
        // 保留期 = u64::MAX：tombstone 生成但永不过期，不得物理删除。
        let cfg = GcConfig {
            retention_secs: u64::MAX,
            max_sweep_per_run: 100_000,
            quota: QuotaPolicy::default(),
        };
        let plan = ws.plan_gc(&cfg).expect("plan ok");
        assert!(!plan.candidates.is_empty(), "旧 state 对象应为候选");
        let n = ws.apply_tombstones(&plan).expect("tombstone ok");
        assert_eq!(n as usize, plan.candidates.len());
        let report = ws.sweep(&cfg, &InFlightSet::new()).expect("sweep ok");
        assert_eq!(report.swept, 0, "保留期内不得物理删除");
        assert_eq!(report.tombstoned, 0, "sweep 本身不生成 tombstone");
        // tombstone 记录仍在：再次 plan 不得出现新的用户数据候选；
        // 仅允许 GC 自身 persist 产生的旧 state（bookkeeping 闭环）。
        let plan2 = ws.plan_gc(&cfg).expect("plan ok");
        assert!(
            plan2
                .candidates
                .iter()
                .all(|(_, r)| *r == GcReason::SupersededState),
            "第二轮不得有非 state 候选：{plan2:?}"
        );
    }

    #[test]
    fn sweep_resurrects_reachable_tombstones() {
        let mut ws = ws_with_commits();
        let cfg = test_config();
        // 取一个候选并 tombstone。
        let plan = ws.plan_gc(&cfg).expect("plan ok");
        assert!(!plan.candidates.is_empty());
        let victim = plan.candidates[0].0.clone();
        ws.apply_tombstones(&plan).expect("tombstone ok");
        // 让 victim 重新可达：pin 住它（pin 进 reachable 闭包）。
        ws.pin(victim.clone());
        let report = ws.sweep(&cfg, &InFlightSet::new()).expect("sweep ok");
        assert_eq!(report.resurrected, 1, "复活的对象应撤销 tombstone");
        // 其余未 pin 的候选照常被扫掉（保留期 0）
        assert_eq!(report.swept, plan.candidates.len() as u64 - 1);
        // tombstone 记录已移除（复活 = 撤销）；unpin 后重新 plan 应再次成为候选。
        ws.unpin(&victim);
        let plan2 = ws.plan_gc(&cfg).expect("plan ok");
        assert!(plan2.candidates.iter().any(|(id, _)| id == &victim));
    }

    #[test]
    fn inflight_blocks_sweep() {
        let mut ws = ws_with_commits();
        let cfg = test_config();
        let plan = ws.plan_gc(&cfg).expect("plan ok");
        assert!(!plan.candidates.is_empty());
        let victim = plan.candidates[0].0.clone();
        ws.apply_tombstones(&plan).expect("tombstone ok");
        let mut inflight = InFlightSet::new();
        inflight.insert(victim.clone());
        let report = ws.sweep(&cfg, &inflight).expect("sweep ok");
        assert_eq!(report.blocked_by_inflight, 1);
        assert!(report.swept < plan.candidates.len() as u64);
        inflight.remove(&victim);
        // 移出 in-flight 后不再 block
        let report2 = ws.sweep(&cfg, &InFlightSet::new()).expect("sweep ok");
        assert_eq!(report2.blocked_by_inflight, 0);
    }

    #[test]
    fn quota_pressure_levels() {
        let q = QuotaPolicy {
            soft_bytes: 100,
            hard_bytes: 200,
        };
        assert_eq!(q.pressure(0), QuotaPressure::None);
        assert_eq!(q.pressure(99), QuotaPressure::None);
        assert_eq!(q.pressure(100), QuotaPressure::Soft);
        assert_eq!(q.pressure(199), QuotaPressure::Soft);
        assert_eq!(q.pressure(200), QuotaPressure::Hard);
        assert_eq!(q.pressure(u64::MAX), QuotaPressure::Hard);
    }

    #[test]
    fn tombstones_survive_reopen() {
        let mut ws = ws_with_commits();
        let cfg = GcConfig {
            retention_secs: u64::MAX,
            max_sweep_per_run: 100_000,
            quota: QuotaPolicy::default(),
        };
        let plan = ws.plan_gc(&cfg).expect("plan ok");
        let n = ws.apply_tombstones(&plan).expect("tombstone ok");
        assert!(n > 0);
        let state_root = ws.state_root().clone();
        let store = ws.into_store();
        // 冷启动恢复
        let ws2 =
            Workspace::open(WorkspaceId("ws-gc-test".into()), store, &state_root).expect("open ok");
        // tombstone 持久化了：同样配置下 sweep 仍不删除
        let mut ws2 = ws2;
        let report = ws2.sweep(&cfg, &InFlightSet::new()).expect("sweep ok");
        assert_eq!(report.swept, 0);
        // 且计划不再重复生成已 tombstone 的候选（仅 GC 自身 bookkeeping 例外）
        let plan2 = ws2.plan_gc(&cfg).expect("plan ok");
        assert!(
            plan2
                .candidates
                .iter()
                .all(|(_, r)| *r == GcReason::SupersededState),
            "重开后不得有非 state 候选：{plan2:?}"
        );
    }

    #[test]
    fn v1_state_still_opens() {
        // v1 格式（无 tombstone/retain/hold/shallow 行）必须能打开。
        let v1 = "nexus-workspace-state v1\nid ws-v1\ncommit C0 abcdef0123456789 \nhead C0\n";
        // 直接走 DurableState 解析路径：用 open 需要 store 里有该对象。
        let mut store = InMemoryContentStore::new();
        let oid = store.put(v1.as_bytes()).expect("put ok");
        // 注意：v1 的 manifest id 是假的，open 会校验 commits 非空/head 非空然后成功；
        // 这里只验证解析不报错（CorruptState）。
        let ws = Workspace::open(WorkspaceId("ws-v1".into()), store, &oid);
        assert!(ws.is_ok(), "v1 state 应向前兼容打开：{ws:?}");
    }

    #[test]
    fn sparse_policy_filters_paths() {
        let p = ReplicaPolicy {
            max_depth: None,
            sparse_paths: vec!["docs/".into(), "src/lib".into()],
        };
        assert!(p.path_wanted("docs/guide.txt"));
        assert!(p.path_wanted("src/lib/mod.rs"));
        assert!(!p.path_wanted("f1.txt"));
        assert!(!p.path_wanted("src/main.rs"));
        let all = ReplicaPolicy::default();
        assert!(all.path_wanted("anything/at/all.txt"));
    }

    #[test]
    fn scheduler_pause_resume_shutdown() {
        use std::sync::{Arc, Mutex};
        let ws = Arc::new(Mutex::new(ws_with_commits()));
        let sched = GcScheduler::spawn(
            Arc::clone(&ws),
            GcSchedulerConfig {
                gc: GcConfig {
                    retention_secs: 0,
                    max_sweep_per_run: 100_000,
                    quota: QuotaPolicy {
                        soft_bytes: 1,
                        hard_bytes: 2,
                    },
                },
                interval_secs: 1,
            },
            Box::new(AlwaysRun),
            Box::new(NoopQuotaHandler),
        );
        sched.pause();
        sched.resume();
        sched.pause();
        // 幂等 shutdown
        sched.shutdown();
        sched.shutdown();
    }
}
