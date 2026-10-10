//! Linux FUSE adapter projecting a workspace as a filesystem (v9 §22).
//!
//! Consumes the portable [`nexus_platform::ProjectedWorkspace`] trait.
//! This adapter owns **no** replica selection, path planning, cache policy,
//! or commit semantics — it only maps FUSE operations onto the trait.
//!
//! Semantics:
//!
//! - Writes stage in the workspace WorkingSet (open → write → release
//!   flushes via `write_file`); nothing is committed implicitly.
//! - [`FuseWorkspaceFs::commit`] persists staged changes; call it from the
//!   host process (the fs handle is `Clone` + `Send`).
//! - Inode numbers are session-scoped (not stable across mounts).
//! - `mkdir` creates an ephemeral in-memory directory overlay (workspace
//!   has no empty-dir concept); it is not committed.
//! - Correctness-first v1: no readdir/attr caching beyond the TTL the
//!   kernel applies; every lookup goes back to the workspace.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

/// Re-export: FUSE background session handle (drop → unmount).
/// C1: daemon 持有它维持挂载。
pub use fuser::BackgroundSession;
use nexus_platform::{PlatformError, ProjectedDirEntry, ProjectedWorkspace};

const TTL: Duration = Duration::from_secs(1);
/// FUSE protocol root inode (stable ABI value).
const ROOT_INO: u64 = 1;

fn now() -> SystemTime {
    SystemTime::now()
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

struct InoEntry {
    path: String,
    parent: u64,
    is_dir: bool,
    size: u64,
}

struct OpenFile {
    path: String,
    buf: Vec<u8>,
    dirty: bool,
}

struct FuseInner {
    ws: Box<dyn ProjectedWorkspace>,
    inodes: HashMap<u64, InoEntry>,
    ino_by_path: HashMap<String, u64>,
    next_ino: u64,
    /// Ephemeral mkdir overlay (not committed; workspace has no empty dirs).
    explicit_dirs: HashSet<String>,
    open: HashMap<u64, OpenFile>,
    next_fh: u64,
    /// C1/D5: true if writes/deletes were staged since the last commit.
    /// Used by the daemon to warn on unmount with uncommitted data
    /// (never silently committed).
    staged_dirty: bool,
}

/// FUSE filesystem projecting a [`ProjectedWorkspace`].
///
/// `Clone` shares the same underlying workspace (interior mutability), so
/// the host keeps a handle for [`FuseWorkspaceFs::commit`] while the
/// mount owns its clone.
#[derive(Clone)]
pub struct FuseWorkspaceFs {
    inner: Arc<Mutex<FuseInner>>,
}

impl FuseWorkspaceFs {
    /// Wrap a projected workspace.
    pub fn new(ws: Box<dyn ProjectedWorkspace>) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            ROOT_INO,
            InoEntry {
                path: String::new(),
                parent: ROOT_INO,
                is_dir: true,
                size: 0,
            },
        );
        let mut ino_by_path = HashMap::new();
        ino_by_path.insert(String::new(), ROOT_INO);
        Self {
            inner: Arc::new(Mutex::new(FuseInner {
                ws,
                inodes,
                ino_by_path,
                next_ino: ROOT_INO + 1,
                explicit_dirs: HashSet::new(),
                open: HashMap::new(),
                next_fh: 1,
                staged_dirty: false,
            })),
        }
    }

    /// Commit staged workspace changes; returns the new commit id.
    pub fn commit(&self) -> Result<String, PlatformError> {
        let mut inner = self.inner.lock().map_err(|_| PlatformError::Io {
            operation: "commit".to_string(),
            message: "fuse inner lock poisoned".to_string(),
        })?;
        let id = inner.ws.commit()?;
        inner.staged_dirty = false;
        Ok(id)
    }

    /// Current workspace head.
    pub fn head(&self) -> Option<String> {
        self.inner.lock().ok()?.ws.head()
    }

    /// Current durable state root (C1/D4), if the channel tracks one.
    pub fn state_root(&self) -> Option<String> {
        self.inner.lock().ok()?.ws.state_root()
    }

    /// C1/D5: true if writes/deletes were staged since the last commit.
    pub fn has_uncommitted_changes(&self) -> bool {
        self.inner.lock().map(|i| i.staged_dirty).unwrap_or(false)
    }

    fn with_inner<T>(
        &self,
        f: impl FnOnce(&mut FuseInner) -> Result<T, Errno>,
    ) -> Result<T, Errno> {
        let mut guard = self.inner.lock().map_err(|_| Errno::EIO)?;
        f(&mut guard)
    }
}

impl FuseInner {
    fn alloc_ino(&mut self, path: String, parent: u64, is_dir: bool, size: u64) -> u64 {
        if let Some(&ino) = self.ino_by_path.get(&path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_by_path.insert(path.clone(), ino);
        self.inodes.insert(
            ino,
            InoEntry {
                path,
                parent,
                is_dir,
                size,
            },
        );
        ino
    }

    /// Resolve `name` under `parent` ino → (ino, is_dir).
    fn resolve(&mut self, parent_ino: u64, name: &str) -> Option<(u64, bool)> {
        let parent_path = self.inodes.get(&parent_ino)?.path.clone();
        let child = join(&parent_path, name);
        if self.explicit_dirs.contains(&child) {
            let ino = self.alloc_ino(child, parent_ino, true, 0);
            return Some((ino, true));
        }
        if let Ok(entries) = self.ws.list_dir(&parent_path) {
            for e in entries {
                if e.name == name {
                    let size = e.size.unwrap_or(0);
                    let ino = self.alloc_ino(child, parent_ino, e.is_dir, size);
                    return Some((ino, e.is_dir));
                }
            }
        }
        None
    }

    fn attr(&self, ino: u64) -> Option<FileAttr> {
        let e = self.inodes.get(&ino)?;
        let t = now();
        Some(FileAttr {
            ino: INodeNo(ino),
            size: e.size,
            blocks: e.size.div_ceil(512),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: if e.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if e.is_dir { 0o755 } else { 0o644 },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
}

fn map_err(op: &'static str, e: PlatformError) -> Errno {
    let _ = op;
    match e {
        PlatformError::NotFound { .. } => Errno::ENOENT,
        PlatformError::Invalid { .. } => Errno::EINVAL,
        PlatformError::Unavailable { .. } => Errno::ENOSYS,
        PlatformError::Io { .. } => Errno::EIO,
    }
}

impl Filesystem for FuseWorkspaceFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = match name.to_str() {
            Some(n) => n.to_string(),
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let res = self.with_inner(|inner| {
            let (ino, _) = inner.resolve(parent.0, &name).ok_or(Errno::ENOENT)?;
            let attr = inner.attr(ino).ok_or(Errno::ENOENT)?;
            Ok(attr)
        });
        match res {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let attr = (|| -> Option<FileAttr> {
            let inner = self.inner.lock().ok()?;
            let e = inner.inodes.get(&ino.0)?;
            if e.is_dir {
                return inner.attr(ino.0);
            }
            // Refresh file size from the workspace (staged writes visible).
            let size = inner.ws.read_file(&e.path).ok()?.len() as u64;
            let mut a = inner.attr(ino.0)?;
            a.size = size;
            a.blocks = size.div_ceil(512);
            Some(a)
        })();
        match attr {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries: Vec<(u64, FileType, String)> = (|| {
            let mut inner = self.inner.lock().ok()?;
            let e = inner.inodes.get(&ino.0)?;
            if !e.is_dir {
                return None;
            }
            let path = e.path.clone();
            let parent = e.parent;
            let mut out = vec![
                (ino.0, FileType::Directory, ".".to_string()),
                (parent, FileType::Directory, "..".to_string()),
            ];
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{path}/")
            };
            let mut overlay: Vec<String> = inner
                .explicit_dirs
                .iter()
                .filter_map(|d| {
                    d.strip_prefix(&prefix)
                        .filter(|rest| !rest.contains('/'))
                        .map(|s| s.to_string())
                })
                .collect();
            overlay.sort();
            let mut ws_entries: Vec<ProjectedDirEntry> =
                inner.ws.list_dir(&path).unwrap_or_default();
            ws_entries.sort_by(|a, b| a.name.cmp(&b.name));
            for name in overlay {
                let child = join(&path, &name);
                let cino = inner.alloc_ino(child, ino.0, true, 0);
                out.push((cino, FileType::Directory, name));
            }
            for de in ws_entries {
                if out.iter().any(|(_, _, n)| n == &de.name) {
                    continue;
                }
                let child = join(&path, &de.name);
                let kind = if de.is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let cino = inner.alloc_ino(child, ino.0, de.is_dir, de.size.unwrap_or(0));
                out.push((cino, kind, de.name));
            }
            Some(out)
        })()
        .unwrap_or_default();
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let res = self.with_inner(|inner| {
            let path = inner.inodes.get(&ino.0).ok_or(Errno::ENOENT)?.path.clone();
            // O_TRUNC (0o1000): the kernel expects the filesystem to truncate
            // on open; without this, a truncated write leaves stale tail bytes.
            let trunc = (flags.0 & 0o1000) != 0;
            let data = if trunc {
                Vec::new()
            } else {
                inner.ws.read_file(&path).map_err(map_err_ws)?
            };
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open.insert(
                fh,
                OpenFile {
                    path,
                    buf: data,
                    // Truncated opens must flush even with no subsequent write.
                    dirty: trunc,
                },
            );
            Ok(fh)
        });
        match res {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let data = (|| -> Option<Vec<u8>> {
            let inner = self.inner.lock().ok()?;
            let f = inner.open.get(&fh.0)?;
            let start = (offset as usize).min(f.buf.len());
            let end = (start + size as usize).min(f.buf.len());
            Some(f.buf[start..end].to_vec())
        })();
        match data {
            Some(d) => reply.data(&d),
            None => reply.error(Errno::EBADF),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let n = (|| -> Option<usize> {
            let mut inner = self.inner.lock().ok()?;
            let f = inner.open.get_mut(&fh.0)?;
            let off = offset as usize;
            if off > f.buf.len() {
                f.buf.resize(off, 0);
            }
            let end = off + data.len();
            if end > f.buf.len() {
                f.buf.resize(end, 0);
            }
            f.buf[off..end].copy_from_slice(data);
            f.dirty = true;
            Some(data.len())
        })();
        match n {
            Some(len) => reply.written(len as u32),
            None => reply.error(Errno::EBADF),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let res = self.with_inner(|inner| {
            let f = inner.open.remove(&fh.0).ok_or(Errno::EBADF)?;
            if f.dirty {
                inner.ws.write_file(&f.path, &f.buf).map_err(map_err_ws)?;
                inner.staged_dirty = true;
            }
            if let Some(ino) = inner.ino_by_path.get(&f.path).copied() {
                if let Some(e) = inner.inodes.get_mut(&ino) {
                    e.size = f.buf.len() as u64;
                }
            }
            Ok(())
        });
        match res {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name = match name.to_str() {
            Some(n) => n.to_string(),
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let res = self.with_inner(|inner| {
            let p = inner.inodes.get(&parent.0).ok_or(Errno::ENOENT)?;
            if !p.is_dir {
                return Err(Errno::ENOTDIR);
            }
            let parent_path = p.path.clone();
            let child = join(&parent_path, &name);
            let ino = inner.alloc_ino(child.clone(), parent.0, false, 0);
            let fh = inner.next_fh;
            inner.next_fh += 1;
            // dirty=true so release() materializes even an empty file.
            inner.open.insert(
                fh,
                OpenFile {
                    path: child,
                    buf: Vec::new(),
                    dirty: true,
                },
            );
            let attr = inner.attr(ino).ok_or(Errno::ENOENT)?;
            Ok((attr, fh))
        });
        match res {
            Ok((attr, fh)) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(fh),
                FopenFlags::empty(),
            ),
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = match name.to_str() {
            Some(n) => n.to_string(),
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let res = self.with_inner(|inner| {
            let parent_path = inner
                .inodes
                .get(&parent.0)
                .ok_or(Errno::ENOENT)?
                .path
                .clone();
            let child = join(&parent_path, &name);
            if let Ok(entries) = inner.ws.list_dir(&parent_path) {
                if entries.iter().any(|e| e.name == name && e.is_dir) {
                    return Err(Errno::EISDIR);
                }
            }
            inner.ws.delete(&child).map_err(map_err_ws)?;
            inner.staged_dirty = true;
            if let Some(ino) = inner.ino_by_path.remove(&child) {
                inner.inodes.remove(&ino);
            }
            Ok(())
        });
        match res {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name = match name.to_str() {
            Some(n) => n.to_string(),
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let res = self.with_inner(|inner| {
            let parent_path = inner
                .inodes
                .get(&parent.0)
                .ok_or(Errno::ENOENT)?
                .path
                .clone();
            let child = join(&parent_path, &name);
            // Ephemeral overlay: workspace has no empty-dir concept.
            inner.explicit_dirs.insert(child.clone());
            let ino = inner.alloc_ino(child, parent.0, true, 0);
            inner.attr(ino).ok_or(Errno::ENOENT)
        });
        match res {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = match name.to_str() {
            Some(n) => n.to_string(),
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let res = self.with_inner(|inner| {
            let parent_path = inner
                .inodes
                .get(&parent.0)
                .ok_or(Errno::ENOENT)?
                .path
                .clone();
            let child = join(&parent_path, &name);
            let ws_empty = inner
                .ws
                .list_dir(&child)
                .map(|v| v.is_empty())
                .unwrap_or(true);
            let overlay_empty = !inner
                .explicit_dirs
                .iter()
                .any(|d| d != &child && d.starts_with(&format!("{child}/")));
            if !ws_empty || !overlay_empty {
                return Err(Errno::ENOTEMPTY);
            }
            inner.explicit_dirs.remove(&child);
            if let Some(ino) = inner.ino_by_path.remove(&child) {
                inner.inodes.remove(&ino);
            }
            Ok(())
        });
        match res {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let res = self.with_inner(|inner| {
            let path = inner.inodes.get(&ino.0).ok_or(Errno::ENOENT)?.path.clone();
            if let Some(new_size) = size {
                let new_size = new_size as usize;
                // Truncate applies to live open buffers first: a setattr
                // without fh (e.g. O_TRUNC via do_truncate) must not diverge
                // from buffers that release() will flush later.
                let mut any_open = false;
                for f in inner.open.values_mut() {
                    if f.path == path {
                        f.buf.resize(new_size, 0);
                        f.dirty = true;
                        any_open = true;
                    }
                }
                if !any_open {
                    let mut data = inner.ws.read_file(&path).map_err(map_err_ws)?;
                    data.resize(new_size, 0);
                    inner.ws.write_file(&path, &data).map_err(map_err_ws)?;
                    inner.staged_dirty = true;
                }
                if let Some(e) = inner.inodes.get_mut(&ino.0) {
                    e.size = new_size as u64;
                }
            }
            inner.attr(ino.0).ok_or(Errno::ENOENT)
        });
        match res {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }
}

fn map_err_ws(e: PlatformError) -> Errno {
    map_err("ws", e)
}

/// Mount a projected workspace at `mountpoint` on a background thread.
///
/// Returns the fs handle (for [`FuseWorkspaceFs::commit`]) and the mount
/// session; dropping the session unmounts.
pub fn mount_projected_workspace(
    ws: Box<dyn ProjectedWorkspace>,
    mountpoint: &Path,
) -> io::Result<(FuseWorkspaceFs, BackgroundSession)> {
    std::fs::create_dir_all(mountpoint)?;
    let fs = FuseWorkspaceFs::new(ws);
    // Note: no AutoUnmount — it requires AllowOther/AllowRoot or a
    // permissive /etc/fuse.conf; drop of BackgroundSession unmounts.
    let mut config = fuser::Config::default();
    config
        .mount_options
        .push(MountOption::FSName("nexus-ws".to_string()));
    let session = fuser::spawn_mount(fs.clone(), mountpoint, &config)?;
    Ok((fs, session))
}

/// Best-effort unmount (used by E4 cleanup; drop of `BackgroundSession`
/// also unmounts).
pub fn unmount_projected_workspace(mountpoint: &Path) {
    for bin in ["fusermount", "fusermount3"] {
        let _ = std::process::Command::new(bin)
            .arg("-u")
            .arg(mountpoint)
            .output();
    }
}

/// C1/D6: idempotent orphan-mount cleanup at daemon startup.
/// Tries `fusermount -u`; if the mountpoint is still mounted afterwards
/// (busy), falls back to lazy unmount (`-uz`). Never fails.
pub fn cleanup_orphan_mount(mountpoint: &Path) {
    if !is_mounted(mountpoint) {
        return;
    }
    for bin in ["fusermount", "fusermount3"] {
        let _ = std::process::Command::new(bin)
            .arg("-u")
            .arg(mountpoint)
            .output();
    }
    if is_mounted(mountpoint) {
        for bin in ["fusermount", "fusermount3"] {
            let _ = std::process::Command::new(bin)
                .arg("-uz")
                .arg(mountpoint)
                .output();
        }
    }
}

/// True if `mountpoint` appears in `/proc/mounts`.
///
/// F6：`/proc/mounts` 对挂载点中的特殊字符做转义（空格→`\040` 等）；
/// 比较前做反转义，否则含空格的显式 mountpoint 会误判。
pub fn is_mounted(mountpoint: &Path) -> bool {
    let target = mountpoint.to_string_lossy();
    std::fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mp| unescape_mount(mp) == target)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// 反转义 `/proc/mounts` 的挂载点字段（`\040` 空格、`\012` 换行、`\134` 反斜杠）。
fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_platform::ProjectedDirEntry;
    use std::collections::HashMap;

    /// In-memory fake for adapter unit tests (no workspace dep).
    struct FakeWs {
        files: HashMap<String, Vec<u8>>,
        commits: u32,
    }

    impl ProjectedWorkspace for FakeWs {
        fn read_file(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
            self.files
                .get(path)
                .cloned()
                .ok_or(PlatformError::NotFound {
                    key: path.to_string(),
                })
        }
        fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), PlatformError> {
            self.files.insert(path.to_string(), content.to_vec());
            Ok(())
        }
        fn list_dir(&self, path: &str) -> Result<Vec<ProjectedDirEntry>, PlatformError> {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{path}/")
            };
            let mut out: HashMap<String, ProjectedDirEntry> = HashMap::new();
            for (k, v) in &self.files {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    if rest.is_empty() {
                        continue;
                    }
                    match rest.find('/') {
                        Some(i) => {
                            out.entry(rest[..i].to_string())
                                .or_insert(ProjectedDirEntry {
                                    name: rest[..i].to_string(),
                                    is_dir: true,
                                    size: None,
                                });
                        }
                        None => {
                            out.insert(
                                rest.to_string(),
                                ProjectedDirEntry {
                                    name: rest.to_string(),
                                    is_dir: false,
                                    size: Some(v.len() as u64),
                                },
                            );
                        }
                    }
                }
            }
            let mut vec: Vec<_> = out.into_values().collect();
            vec.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(vec)
        }
        fn delete(&mut self, path: &str) -> Result<(), PlatformError> {
            self.files
                .remove(path)
                .map(|_| ())
                .ok_or(PlatformError::NotFound {
                    key: path.to_string(),
                })
        }
        fn commit(&mut self) -> Result<String, PlatformError> {
            self.commits += 1;
            Ok(format!("c{}", self.commits))
        }
        fn head(&self) -> Option<String> {
            if self.commits == 0 {
                None
            } else {
                Some(format!("c{}", self.commits))
            }
        }
    }

    fn test_fs() -> FuseWorkspaceFs {
        FuseWorkspaceFs::new(Box::new(FakeWs {
            files: HashMap::new(),
            commits: 0,
        }))
    }

    #[test]
    fn adapter_does_not_own_commit_semantics() {
        // Writes stage; nothing is committed implicitly.
        let fs = test_fs();
        assert_eq!(fs.head(), None);
        let c1 = fs.commit().unwrap();
        assert_eq!(c1, "c1");
        assert_eq!(fs.head().as_deref(), Some("c1"));
    }

    #[test]
    fn path_join_helpers() {
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("d", "a"), "d/a");
    }

    #[test]
    fn fuse_fs_is_send_sync_and_clone() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FuseWorkspaceFs>();
        let fs = test_fs();
        let _ = fs.clone();
    }

    #[test]
    fn map_err_covers_platform_errors() {
        assert_eq!(
            map_err("op", PlatformError::NotFound { key: "k".into() }),
            Errno::ENOENT
        );
        assert_eq!(
            map_err(
                "op",
                PlatformError::Invalid {
                    message: "m".into()
                }
            ),
            Errno::EINVAL
        );
        assert_eq!(
            map_err(
                "op",
                PlatformError::Io {
                    operation: "o".into(),
                    message: "m".into()
                }
            ),
            Errno::EIO
        );
    }
}
