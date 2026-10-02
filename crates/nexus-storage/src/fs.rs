//! 落盘内容寻址存储（`FsContentStore`）。
//!
//! 布局：`<dir>/<object-id>`（hex16 文件名，扁平目录）。
//! 写语义：temp 文件 + fsync + 原子 rename（crash-consistent，满足 MODULE
//! "关键更新必须 crash-consistent" 不变量）；内容寻址保证同字节同 id，
//! 已存在对象直接复用（不重写，mtime 即首次写入时间，供 GC 保留期使用）。
//!
//! 副作用归属：文件系统写（本模块的 Responsibility 明确要求持久化）。

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{ContentStore, ObjectId, ReachabilityGc, StorageStats, object_id_of};

/// 落盘 CAS：`<dir>/` 下每个对象一个文件，文件名为 [`ObjectId`]。
#[derive(Debug)]
pub struct FsContentStore {
    dir: PathBuf,
    protected: HashSet<ObjectId>,
    tmp_seq: AtomicU64,
}

impl FsContentStore {
    /// 打开（不存在则创建）落盘 CAS 目录。
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create cas dir {}: {e}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            protected: HashSet::new(),
            tmp_seq: AtomicU64::new(0),
        })
    }

    /// CAS 根目录。
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 文件名是否安全（只允许字母数字/`-`/`_`；拒绝 `/`、`..`、点文件）。
    fn safe_name(id: &ObjectId) -> bool {
        !id.0.is_empty()
            && id.0.len() <= 128
            && id
                .0
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    fn path_of(&self, id: &ObjectId) -> Option<PathBuf> {
        if Self::safe_name(id) {
            Some(self.dir.join(&id.0))
        } else {
            None
        }
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 原子写：temp + fsync(file) + rename + fsync(dir)。
    fn atomic_write(&self, id: &ObjectId, bytes: &[u8]) -> Result<(), String> {
        let target = self
            .path_of(id)
            .ok_or_else(|| format!("unsafe object id: {:?}", id.0))?;
        if target.exists() {
            return Ok(()); // 内容寻址：同 id 即同字节，幂等复用。
        }
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!(".tmp-{}-{seq}", std::process::id()));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| format!("create tmp object: {e}"))?;
            f.write_all(bytes)
                .map_err(|e| format!("write tmp object: {e}"))?;
            f.sync_all().map_err(|e| format!("fsync tmp object: {e}"))?;
        }
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("rename object into cas: {e}")
        })?;
        // 目录 fsync，保证 rename 本身 crash 后可见。
        if let Ok(dir_fd) = OpenOptions::new().read(true).open(&self.dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    }

    /// 测试辅助：设置对象的 mtime（模拟"旧对象"，验证保留期语义）。
    #[cfg(test)]
    fn set_stored_at_unix(&self, id: &ObjectId, ts: u64) -> Result<(), String> {
        #[cfg(unix)]
        {
            let path = self
                .path_of(id)
                .ok_or_else(|| format!("unsafe object id: {:?}", id.0))?;
            let status = std::process::Command::new("touch")
                .arg("-d")
                .arg(format!("@{ts}"))
                .arg(&path)
                .status()
                .map_err(|e| format!("spawn touch: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("touch -d failed for {}", path.display()))
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (id, ts);
            Err("set_stored_at_unix only supported on unix".to_string())
        }
    }
}

impl ContentStore for FsContentStore {
    fn contains(&self, id: &ObjectId) -> Result<bool, String> {
        Ok(self.path_of(id).map(|p| p.is_file()).unwrap_or(false))
    }

    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String> {
        match self.path_of(id) {
            Some(p) => match std::fs::read(&p) {
                Ok(b) => Ok(Some(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("read object {}: {e}", id.0)),
            },
            None => Ok(None),
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<ObjectId, String> {
        let id = object_id_of(bytes);
        self.atomic_write(&id, bytes)?;
        Ok(id)
    }

    fn object_ids(&self) -> Result<Vec<ObjectId>, String> {
        let mut ids = Vec::new();
        let entries = std::fs::read_dir(&self.dir).map_err(|e| format!("list cas dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read cas entry: {e}"))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // 跳过 temp 文件与点文件。
            if name.starts_with('.') {
                continue;
            }
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                ids.push(ObjectId(name.into_owned()));
            }
        }
        Ok(ids)
    }
}

impl StorageStats for FsContentStore {
    fn usage_bytes(&self) -> Result<u64, String> {
        let mut total: u64 = 0;
        for id in self.object_ids()? {
            if let Some(p) = self.path_of(&id) {
                if let Ok(md) = std::fs::metadata(&p) {
                    total = total.saturating_add(md.len());
                }
            }
        }
        Ok(total)
    }
}

impl ReachabilityGc for FsContentStore {
    fn mark_roots(&mut self, roots: &[ObjectId]) -> Result<(), String> {
        self.protected.extend(roots.iter().cloned());
        Ok(())
    }

    fn sweep_older_than(&mut self, retention_seconds: u64) -> Result<u64, String> {
        let now = Self::now_unix();
        let mut removed: u64 = 0;
        for id in self.object_ids()? {
            if self.protected.contains(&id) {
                continue;
            }
            let Some(path) = self.path_of(&id) else {
                continue;
            };
            let mtime = std::fs::metadata(&path)
                .ok()
                .and_then(|md| md.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(now);
            let within_retention = now.saturating_sub(mtime) <= retention_seconds;
            if !within_retention {
                match std::fs::remove_file(&path) {
                    Ok(()) => removed += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("sweep remove {}: {e}", id.0)),
                }
            }
        }
        Ok(removed)
    }

    fn delete_object(&mut self, id: &ObjectId) -> Result<bool, String> {
        // 与 InMemoryContentStore 同语义：tombstone 两阶段由调用方
        // （nexus-workspace GC）保证；这里不二次检查 protected。
        match self.path_of(id) {
            Some(p) => match std::fs::remove_file(&p) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(format!("delete object {}: {e}", id.0)),
            },
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nexus-fs-cas-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempdir();
        let mut s = FsContentStore::open(&dir).unwrap();
        let id = s.put(b"hello-cas").unwrap();
        assert!(s.contains(&id).unwrap());
        assert_eq!(s.get(&id).unwrap(), Some(b"hello-cas".to_vec()));
        assert_eq!(s.get(&ObjectId("deadbeef".into())).unwrap(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_persists() {
        let dir = tempdir();
        let id = {
            let mut s = FsContentStore::open(&dir).unwrap();
            s.put(b"persist-me").unwrap()
        };
        // drop 后重开：数据仍在（crash-consistent 语义）。
        let s2 = FsContentStore::open(&dir).unwrap();
        assert_eq!(s2.get(&id).unwrap(), Some(b"persist-me".to_vec()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_idempotent_keeps_first_mtime() {
        let dir = tempdir();
        let mut s = FsContentStore::open(&dir).unwrap();
        let id1 = s.put(b"same-bytes").unwrap();
        let id2 = s.put(b"same-bytes").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(s.object_ids().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unsafe_id_rejected() {
        let dir = tempdir();
        let s = FsContentStore::open(&dir).unwrap();
        assert!(!s.contains(&ObjectId("../evil".into())).unwrap());
        assert_eq!(s.get(&ObjectId("../../x".into())).unwrap(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn sweep_respects_retention_and_roots() {
        let dir = tempdir();
        let mut s = FsContentStore::open(&dir).unwrap();
        let now = FsContentStore::now_unix();
        let old = s.put(b"old-object").unwrap();
        let young = s.put(b"young-object").unwrap();
        let pinned = s.put(b"pinned-old").unwrap();
        s.set_stored_at_unix(&old, now - 2_000_000).unwrap();
        s.set_stored_at_unix(&pinned, now - 2_000_000).unwrap();
        s.mark_roots(std::slice::from_ref(&pinned)).unwrap();

        // 保留期 14 天：old 被扫掉，pinned（protected）和 young 保留。
        let removed = s.sweep_older_than(14 * 24 * 3600).unwrap();
        assert_eq!(removed, 1);
        assert!(!s.contains(&old).unwrap());
        assert!(s.contains(&pinned).unwrap());
        assert!(s.contains(&young).unwrap());

        // usage_bytes 只计存活对象。
        let usage = s.usage_bytes().unwrap();
        assert_eq!(usage, (b"pinned-old".len() + b"young-object".len()) as u64);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_object_semantics() {
        let dir = tempdir();
        let mut s = FsContentStore::open(&dir).unwrap();
        let id = s.put(b"to-delete").unwrap();
        assert!(s.delete_object(&id).unwrap());
        assert!(!s.delete_object(&id).unwrap());
        assert!(!s.delete_object(&ObjectId("nope".into())).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }
}
