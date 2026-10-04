//! IntelStore：智能状态的独立持久化（v9 §21"可丢失并重建"）。
//!
//! 存储内容：访问轨迹 + profiles（图可由二者重建，不单独存）。
//! 存储位置与权威 workspace 状态**物理隔离**（独立文件）。
//! 删除本文件 = Deletion Test：workspace 正确性不受影响，智能从新轨迹重建。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use crate::trace::{AccessEvent, AccessTrace};

/// 可序列化的智能快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSnapshot {
    pub version: u32,
    pub trace: Vec<AccessEvent>,
    pub profiles: Vec<Profile>,
}

impl IntelSnapshot {
    pub const VERSION: u32 = 1;
}

/// 独立持久化句柄。
#[derive(Debug, Clone)]
pub struct IntelStore {
    path: PathBuf,
}

impl IntelStore {
    /// 绑定到独立文件路径（调用方保证与权威状态文件不同）。
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// 保存轨迹 + profiles（原子写：tmp + rename）。
    pub fn save(&self, trace: &AccessTrace, profiles: &[Profile]) -> io::Result<()> {
        let snap = IntelSnapshot {
            version: IntelSnapshot::VERSION,
            trace: trace.events().to_vec(),
            profiles: profiles.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&snap)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// 加载（文件不存在 → `Ok(None)`，视为全新智能状态）。
    pub fn load(&self) -> io::Result<Option<(AccessTrace, Vec<Profile>)>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&self.path)?;
        let snap: IntelSnapshot = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut trace = AccessTrace::new();
        for e in snap.trace {
            trace.record(&e.path, e.at_unix);
        }
        Ok(Some((trace, snap.profiles)))
    }

    /// 删除智能状态（Deletion Test 入口）。权威 workspace 数据不受影响。
    pub fn delete(&self) -> io::Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_delete_roundtrip() {
        let dir = std::env::temp_dir().join("ws-intel-store-test");
        let _ = std::fs::create_dir_all(&dir);
        let store = IntelStore::new(&dir.join("intel.json"));
        let _ = store.delete();

        assert!(store.load().unwrap().is_none());

        let mut trace = AccessTrace::new();
        trace.record("a", 1);
        let profiles = vec![Profile::declare("p", vec!["a".into()], 1.0)];
        store.save(&trace, &profiles).unwrap();

        let (t2, p2) = store.load().unwrap().unwrap();
        assert_eq!(t2.len(), 1);
        assert_eq!(p2.len(), 1);

        // Deletion：删后回到全新状态
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
