//! nexusd Workspace 生产接线（C1）。
//!
//! - `workspace.toml` 的 `[[workspace]]` → 打开/创建 Workspace → FUSE 挂载。
//! - 持久化：各 workspace 共享落盘 CAS（`<data-dir>/cas/`，[`FsContentStore`]）+
//!   每个 workspace 的 `<data-dir>/workspaces/<id>/state_root` 锚文件（原子写，
//!   启动 `open` 用；每次 commit 后更新）。
//! - 生命周期：orphan mount 幂等清理（D6）→ 挂载 → 持有 `BackgroundSession`；
//!   关闭时先 warn 脏数据（D5，不静默提交）再 unmount（D7 顺序中的一步）。
//! - D8：无 `/dev/fuse` 时记 warn、不启用 workspace 子系统，不静默 fallback。
//!
//! 本模块只在 Linux 编译（FUSE 挂载是平台能力，由 Composition Root 装配，
//! 符合 AGENTS.md §11）。

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use nexus_platform_linux::fuse_ws::{
    BackgroundSession, FuseWorkspaceFs, cleanup_orphan_mount, is_mounted,
    mount_projected_workspace, unmount_projected_workspace,
};
use nexus_storage::{FsContentStore, ObjectId};
use nexus_workspace::{
    AuthorId, NativeApiWorkspaceAccess, Workspace, WorkspaceId, WorkspaceProjection,
};

/// `workspace.toml` 中单个 `[[workspace]]` 条目。
#[derive(Debug, Clone)]
pub struct WorkspaceEntry {
    /// Workspace id（用作目录名；只允许字母数字/`-`/`_`）。
    pub id: String,
    /// 显式挂载点；缺省 `<data-dir>/mounts/<id>`（D2）。
    pub mountpoint: Option<PathBuf>,
    /// 新提交的 author；缺省为 workspace id。
    pub author: String,
    /// 定时自动提交间隔（秒）；0 = 关闭（D5，默认关）。
    pub auto_commit_secs: u64,
}

/// 解析 `workspace.toml` 全文 → 条目列表（深层语义校验）。
pub fn parse_workspace_toml(text: &str) -> Result<Vec<WorkspaceEntry>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("parse workspace.toml: {e}"))?;
    let arr = v
        .get("workspace")
        .and_then(|w| w.as_array())
        .ok_or_else(|| "workspace.toml: missing [[workspace]] entries".to_string())?;
    if arr.is_empty() {
        return Err("workspace.toml: [[workspace]] is empty".to_string());
    }
    let mut entries = Vec::with_capacity(arr.len());
    let mut seen_ids = std::collections::HashSet::new();
    for (i, item) in arr.iter().enumerate() {
        let ctx = format!("workspace.toml: [[workspace]] #{i}");
        let id = item
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("{ctx}: missing id"))?;
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("{ctx}: bad id {id:?}"));
        }
        if !seen_ids.insert(id.to_string()) {
            return Err(format!("{ctx}: duplicate id {id:?}"));
        }
        let mountpoint = match item.get("mountpoint").and_then(|x| x.as_str()) {
            Some(mp) => {
                let p = PathBuf::from(mp);
                if !p.is_absolute() {
                    return Err(format!("{ctx}: mountpoint must be absolute: {mp:?}"));
                }
                Some(p)
            }
            None => None,
        };
        let author = item
            .get("author")
            .and_then(|x| x.as_str())
            .unwrap_or(id)
            .to_string();
        if author.is_empty() {
            return Err(format!("{ctx}: author must not be empty"));
        }
        let auto_commit_secs = item
            .get("auto_commit_secs")
            .and_then(|x| x.as_integer())
            .unwrap_or(0)
            .max(0) as u64;
        entries.push(WorkspaceEntry {
            id: id.to_string(),
            mountpoint,
            author,
            auto_commit_secs,
        });
    }
    // 显式挂载点不得冲突。
    let mut seen_mp = std::collections::HashSet::new();
    for e in &entries {
        if let Some(mp) = &e.mountpoint {
            if !seen_mp.insert(mp.clone()) {
                return Err(format!(
                    "workspace.toml: duplicate mountpoint {}",
                    mp.display()
                ));
            }
        }
    }
    Ok(entries)
}

/// 原子写小文件（temp + rename）。
fn atomic_write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename {}: {e}", path.display())
    })?;
    Ok(())
}

/// 单个已挂载 workspace 的可共享句柄（commit 路径；`FuseWorkspaceFs` 内部已有锁）。
#[derive(Clone)]
struct WorkspaceHandle {
    fs: FuseWorkspaceFs,
    state_root_path: PathBuf,
}

impl WorkspaceHandle {
    /// 提交暂存变更 → 更新 state_root 锚文件 → 返回新 head。
    fn commit(&self) -> Result<String, String> {
        let new_head = self
            .fs
            .commit()
            .map_err(|e| format!("workspace commit: {e:?}"))?;
        if let Some(sr) = self.fs.state_root() {
            atomic_write_file(&self.state_root_path, sr.as_bytes())?;
        }
        Ok(new_head)
    }
}

/// 已挂载的 workspace（持有 FUSE session；drop 前必须显式 shutdown）。
struct MountedWorkspace {
    id: String,
    mountpoint: PathBuf,
    handle: WorkspaceHandle,
    _session: BackgroundSession,
    auto_commit: Option<AutoCommitThread>,
}

/// 定时自动提交线程（D5；默认关闭）。
struct AutoCommitThread {
    shutdown_tx: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AutoCommitThread {
    fn spawn(id: String, handle: WorkspaceHandle, interval_secs: u64) -> Self {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(format!("nexusd-ws-autocommit-{id}"))
            .spawn(move || {
                loop {
                    match shutdown_rx.recv_timeout(Duration::from_secs(interval_secs)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if handle.fs.has_uncommitted_changes() {
                                match handle.commit() {
                                    Ok(head) => {
                                        eprintln!("[nexusd] workspace {id}: auto-commit → {head}")
                                    }
                                    Err(e) => eprintln!(
                                        "[nexusd] workspace {id}: auto-commit failed: {e}"
                                    ),
                                }
                            }
                        }
                    }
                }
            })
            .expect("spawn workspace auto-commit thread");
        Self {
            shutdown_tx,
            thread: Some(thread),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// LocalAPI `/localapi/v0/workspace/mounts` 的单条状态。
#[derive(Debug, Clone)]
pub struct MountStatus {
    pub id: String,
    pub mountpoint: String,
    pub head: Option<String>,
    pub has_uncommitted_changes: bool,
}

/// Daemon 的 workspace 子系统（Composition Root 装配）。
pub struct WorkspaceManager {
    mounts: Vec<MountedWorkspace>,
    /// D8：无 /dev/fuse 时为 false（warn 后不启用）。
    pub fuse_available: bool,
}

impl WorkspaceManager {
    /// daemon 数据目录（派生，不可配；v1 约定）。
    pub fn data_dir(config_dir: &Path) -> PathBuf {
        config_dir.join("data")
    }

    /// 启动：解析 → orphan 清理 → open-or-create → 挂载。
    ///
    /// D8：无 `/dev/fuse` → warn + 返回 disabled manager（mounts 为空），不报错。
    pub fn start(config_dir: &Path, toml_text: &str) -> Result<Self, String> {
        let entries = parse_workspace_toml(toml_text)?;
        if !Path::new("/dev/fuse").exists() {
            eprintln!(
                "[nexusd] WARN: /dev/fuse not present; workspace mounts disabled (D8, no silent fallback)"
            );
            return Ok(Self {
                mounts: Vec::new(),
                fuse_available: false,
            });
        }
        let data_dir = Self::data_dir(config_dir);
        let cas_dir = data_dir.join("cas");
        let mounts_dir = data_dir.join("mounts");
        let ws_base = data_dir.join("workspaces");
        std::fs::create_dir_all(&cas_dir)
            .map_err(|e| format!("create {}: {e}", cas_dir.display()))?;
        std::fs::create_dir_all(&mounts_dir)
            .map_err(|e| format!("create {}: {e}", mounts_dir.display()))?;

        let mut mounts = Vec::with_capacity(entries.len());
        for e in entries {
            let mountpoint = e
                .mountpoint
                .clone()
                .unwrap_or_else(|| mounts_dir.join(&e.id));
            // D6：幂等清理 orphan mount。
            cleanup_orphan_mount(&mountpoint);
            std::fs::create_dir_all(&mountpoint)
                .map_err(|e| format!("create mountpoint {}: {e}", mountpoint.display()))?;

            let ws_dir = ws_base.join(&e.id);
            std::fs::create_dir_all(&ws_dir)
                .map_err(|e| format!("create {}: {e}", ws_dir.display()))?;
            let state_root_path = ws_dir.join("state_root");

            let store = FsContentStore::open(&cas_dir).map_err(|e| format!("open cas: {e}"))?;
            let workspace: Workspace<FsContentStore> = if state_root_path.is_file() {
                let sr_text = std::fs::read_to_string(&state_root_path)
                    .map_err(|e| format!("read state_root: {e}"))?;
                let sr = sr_text.trim().to_string();
                if sr.is_empty() {
                    return Err(format!("workspace {}: state_root file is empty", e.id));
                }
                Workspace::open(
                    WorkspaceId(e.id.clone()),
                    store,
                    &ObjectId(sr),
                    AuthorId(e.author.clone()),
                )
                .map_err(|e| format!("open workspace: {e:?}"))?
            } else {
                let ws =
                    Workspace::init(WorkspaceId(e.id.clone()), store, AuthorId(e.author.clone()))
                        .map_err(|e| format!("init workspace: {e:?}"))?;
                let sr = ws.state_root().0.clone();
                atomic_write_file(&state_root_path, sr.as_bytes())?;
                ws
            };

            let access = NativeApiWorkspaceAccess::new(workspace);
            let proj = WorkspaceProjection::new(access);
            let (fs, session) = mount_projected_workspace(Box::new(proj), &mountpoint)
                .map_err(|err| format!("mount {} at {}: {err}", e.id, mountpoint.display()))?;
            eprintln!(
                "[nexusd] workspace {} mounted at {}",
                e.id,
                mountpoint.display()
            );

            let handle = WorkspaceHandle {
                fs,
                state_root_path,
            };
            let auto_commit = if e.auto_commit_secs > 0 {
                Some(AutoCommitThread::spawn(
                    e.id.clone(),
                    handle.clone(),
                    e.auto_commit_secs,
                ))
            } else {
                None
            };
            mounts.push(MountedWorkspace {
                id: e.id,
                mountpoint,
                handle,
                _session: session,
                auto_commit,
            });
        }
        Ok(Self {
            mounts,
            fuse_available: true,
        })
    }

    /// 是否启用（D1：workspace.toml 缺失时 manager 为 None，由调用方处理）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// LocalAPI 状态快照。
    #[must_use]
    pub fn mounts_status(&self) -> Vec<MountStatus> {
        self.mounts
            .iter()
            .map(|m| MountStatus {
                id: m.id.clone(),
                mountpoint: m.mountpoint.to_string_lossy().into_owned(),
                head: m.handle.fs.head(),
                has_uncommitted_changes: m.handle.fs.has_uncommitted_changes(),
            })
            .collect()
    }

    /// D5：显式提交（`nexus workspace commit <id>` 经 LocalAPI）。
    pub fn commit(&self, id: &str) -> Result<String, String> {
        let m = self
            .mounts
            .iter()
            .find(|m| m.id == id)
            .ok_or_else(|| format!("unknown workspace: {id}"))?;
        m.handle.commit()
    }

    /// D7：关闭（LocalAPI 之后、Dataplane 之前由调用方排序）。
    /// D5：有未提交变更 → warn，不静默提交。
    pub fn shutdown(mut self) {
        for mut m in self.mounts.drain(..) {
            if let Some(ac) = m.auto_commit.as_mut() {
                ac.shutdown();
            }
            if m.handle.fs.has_uncommitted_changes() {
                eprintln!(
                    "[nexusd] WARN: workspace {} has uncommitted changes at shutdown; \
                     NOT committing (D5: nothing is committed implicitly). \
                     Run `nexus workspace commit {}` to persist.",
                    m.id, m.id
                );
            }
            // 显式 unmount（BackgroundSession drop 也会卸，但这里顺序明确）。
            unmount_projected_workspace(&m.mountpoint);
            if is_mounted(&m.mountpoint) {
                eprintln!(
                    "[nexusd] WARN: mountpoint {} still mounted after unmount",
                    m.mountpoint.display()
                );
            }
            drop(m._session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_entry() {
        let entries = parse_workspace_toml("[[workspace]]\nid = \"ws1\"\n").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "ws1");
        assert_eq!(entries[0].mountpoint, None);
        assert_eq!(entries[0].author, "ws1");
        assert_eq!(entries[0].auto_commit_secs, 0);
    }

    #[test]
    fn parse_full_entry() {
        let entries = parse_workspace_toml(
            "[[workspace]]\nid = \"ws-2\"\nmountpoint = \"/mnt/ws2\"\nauthor = \"alice\"\nauto_commit_secs = 300\n",
        )
        .unwrap();
        let e = &entries[0];
        assert_eq!(e.mountpoint, Some(PathBuf::from("/mnt/ws2")));
        assert_eq!(e.author, "alice");
        assert_eq!(e.auto_commit_secs, 300);
    }

    #[test]
    fn parse_rejects_bad() {
        assert!(parse_workspace_toml("").is_err());
        assert!(parse_workspace_toml("[[workspace]]\n").is_err()); // 缺 id
        assert!(parse_workspace_toml("[[workspace]]\nid = \"../evil\"\n").is_err());
        assert!(
            parse_workspace_toml("[[workspace]]\nid = \"a\"\n[[workspace]]\nid = \"a\"\n").is_err()
        ); // 重复 id
        assert!(
            parse_workspace_toml("[[workspace]]\nid = \"a\"\nmountpoint = \"relative/path\"\n")
                .is_err()
        ); // 相对挂载点
        assert!(parse_workspace_toml(
            "[[workspace]]\nid = \"a\"\nmountpoint = \"/m\"\n[[workspace]]\nid = \"b\"\nmountpoint = \"/m\"\n"
        )
        .is_err()); // 挂载点冲突
    }

    #[test]
    fn start_without_fuse_is_disabled_not_error() {
        // 沙盒无 /dev/fuse：D8 要求 warn + disabled，不报错。
        if Path::new("/dev/fuse").exists() {
            return;
        }
        let d = std::env::temp_dir().join(format!("nexusd-ws-test-{}", std::process::id()));
        let mgr = WorkspaceManager::start(&d, "[[workspace]]\nid = \"ws1\"\n").unwrap();
        assert!(!mgr.fuse_available);
        assert!(mgr.is_empty());
        std::fs::remove_dir_all(d.join("data")).ok();
    }
}
