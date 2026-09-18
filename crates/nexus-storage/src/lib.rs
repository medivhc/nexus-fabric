//! Content-addressed local storage abstractions and an in-memory implementation.
//!
//! 内容对象按 hash 寻址（PRODUCT §4 / nexus-storage MODULE.md）：相同字节序列
//! 产生相同 `ObjectId`；删除只允许由 Reachability GC 在 protected roots 之外、
//! 且超过安全保留期后执行。
//!
//! 本 crate 为 portable-core：零平台依赖，仅 std。

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

/// 内容寻址的对象标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub String);

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// FNV-1a 64 位内容哈希（确定性、零依赖、跨进程稳定）。
/// 用于把任意字节序列映射为 16 位 hex 的 `ObjectId`。
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// 内容寻址：相同字节 → 相同 `ObjectId`。
pub fn object_id_of(bytes: &[u8]) -> ObjectId {
    ObjectId(format!("{:016x}", fnv1a_64(bytes)))
}

/// 内容寻址存储契约。
pub trait ContentStore {
    fn contains(&self, id: &ObjectId) -> Result<bool, String>;
    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String>;
    fn put(&mut self, bytes: &[u8]) -> Result<ObjectId, String>;
}

/// 可达性 GC 契约：只允许回收不再被 protected roots 可达且超过安全保留期的对象。
pub trait ReachabilityGc {
    fn mark_roots(&mut self, roots: &[ObjectId]) -> Result<(), String>;
    fn sweep_older_than(&mut self, retention_seconds: u64) -> Result<u64, String>;
}

#[derive(Debug, Clone)]
struct StoredObject {
    bytes: Vec<u8>,
    stored_at_unix: u64,
}

/// 内存内容寻址存储（确定性、可重放；用于 portable-core 测试与 E4 场景）。
#[derive(Debug, Default)]
pub struct InMemoryContentStore {
    objects: HashMap<ObjectId, StoredObject>,
    protected: HashSet<ObjectId>,
}

impl InMemoryContentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前对象总数（缓存快照观察出口，PRODUCT §9 workspace cache）。
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// 当前 protected root 数（GC 保护观察出口，PRODUCT §9 workspace cache）。
    #[must_use]
    pub fn protected_count(&self) -> usize {
        self.protected.len()
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 测试辅助：以指定时间戳写入（用于验证保留期语义）。
    #[cfg(test)]
    fn put_at(&mut self, bytes: &[u8], stored_at_unix: u64) -> Result<ObjectId, String> {
        let id = object_id_of(bytes);
        self.objects.entry(id.clone()).or_insert(StoredObject {
            bytes: bytes.to_vec(),
            stored_at_unix,
        });
        Ok(id)
    }
}

impl ContentStore for InMemoryContentStore {
    fn contains(&self, id: &ObjectId) -> Result<bool, String> {
        Ok(self.objects.contains_key(id))
    }

    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String> {
        Ok(self.objects.get(id).map(|o| o.bytes.clone()))
    }

    fn put(&mut self, bytes: &[u8]) -> Result<ObjectId, String> {
        let now = Self::now_unix();
        let id = object_id_of(bytes);
        self.objects.entry(id.clone()).or_insert(StoredObject {
            bytes: bytes.to_vec(),
            stored_at_unix: now,
        });
        Ok(id)
    }
}

impl ReachabilityGc for InMemoryContentStore {
    fn mark_roots(&mut self, roots: &[ObjectId]) -> Result<(), String> {
        self.protected.extend(roots.iter().cloned());
        Ok(())
    }

    fn sweep_older_than(&mut self, retention_seconds: u64) -> Result<u64, String> {
        let now = Self::now_unix();
        let mut removed: u64 = 0;
        self.objects.retain(|id, obj| {
            let protected = self.protected.contains(id);
            let within_retention = now.saturating_sub(obj.stored_at_unix) <= retention_seconds;
            let keep = protected || within_retention;
            if !keep {
                removed += 1;
            }
            keep
        });
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressing_is_deterministic() {
        let a = object_id_of(b"hello nexus");
        let b = object_id_of(b"hello nexus");
        let c = object_id_of(b"hello nexuS");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn put_get_roundtrip_and_idempotent_put() {
        let mut store = InMemoryContentStore::new();
        let id = store.put(b"blob-1").expect("put ok");
        assert!(store.contains(&id).expect("contains ok"));
        assert_eq!(store.get(&id).expect("get ok"), Some(b"blob-1".to_vec()));
        // 幂等：相同内容返回相同 id，且不重复占用。
        let id2 = store.put(b"blob-1").expect("put ok");
        assert_eq!(id, id2);
    }

    #[test]
    fn gc_protects_roots_and_respects_retention() {
        let mut store = InMemoryContentStore::new();
        let root = store.put(b"root").expect("put ok");
        let old = store.put_at(b"old", 1_000).expect("put_at ok");
        let recent = store.put_at(b"recent", u64::MAX).expect("put_at ok");

        store
            .mark_roots(std::slice::from_ref(&root))
            .expect("mark ok");

        // 保留期 0：未受保护且“已超保留期”的对象被回收，受保护根永不清除。
        let removed = store.sweep_older_than(0).expect("sweep ok");
        assert_eq!(removed, 1);
        assert!(store.contains(&root).expect("contains ok"));
        assert!(!store.contains(&old).expect("contains ok"));
        assert!(store.contains(&recent).expect("contains ok"));
    }
}
