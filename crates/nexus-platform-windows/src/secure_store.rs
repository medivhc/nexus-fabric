//! Windows SecureStore：DPAPI 加密持久化。
//!
//! 本模块不含 `unsafe`（全部集中在 `dpapi.rs`）；键→文件名映射、错误映射为
//! 纯逻辑。DPAPI 绑定当前 Windows 用户 + 机器，无需管理员（PRODUCT §12.22）。

use crate::dpapi;
use nexus_platform::{PlatformError, SecureStore};
use std::path::PathBuf;

/// 后端标识。
pub const BACKEND: &str = "dpapi";

/// DPAPI 加密的键值存储：每个键一个密文文件（`<dir>/<key>.dpapi`）。
///
/// `get` 缺失键 → `Ok(None)`；`put` 幂等覆盖。文件内容为 DPAPI blob
/// （绑定当前用户+机器，跨用户/跨机器不可解密）。
pub struct DpapiSecureStore {
    dir: PathBuf,
}

impl DpapiSecureStore {
    /// 创建指向目录的 DPAPI store（目录不存在时懒创建）。
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// 键 → 文件名（纯函数）：拒绝空键与路径分隔符，防目录穿越。
    fn key_file(&self, key: &str) -> Result<PathBuf, PlatformError> {
        if key.is_empty() {
            return Err(PlatformError::Invalid {
                message: "secure store key is empty".into(),
            });
        }
        if key.contains('/') || key.contains('\\') || key.contains('.') {
            return Err(PlatformError::Invalid {
                message: format!("secure store key contains invalid chars: {key}"),
            });
        }
        Ok(self.dir.join(format!("{key}.dpapi")))
    }
}

impl SecureStore for DpapiSecureStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        let path = self.key_file(key)?;
        let Ok(cipher) = std::fs::read(&path) else {
            return Ok(None);
        };
        dpapi::unprotect(&cipher)
            .map(Some)
            .map_err(|e| PlatformError::Io {
                operation: "dpapi unprotect".into(),
                message: e.to_string(),
            })
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), PlatformError> {
        let path = self.key_file(key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| PlatformError::Io {
                operation: "dpapi mkdir".into(),
                message: e.to_string(),
            })?;
        }
        let cipher = dpapi::protect(value).map_err(|e| PlatformError::Io {
            operation: "dpapi protect".into(),
            message: e.to_string(),
        })?;
        std::fs::write(&path, cipher).map_err(|e| PlatformError::Io {
            operation: "dpapi write".into(),
            message: e.to_string(),
        })
    }
}

/// DPAPI 能力声明：Windows 上始终可用（无需管理员）。
#[must_use]
pub const fn available() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nexus-dpapi-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn put_get_roundtrip_and_missing() {
        let store = DpapiSecureStore::new(tmp_dir("rt"));
        assert!(store.get("absent").unwrap().is_none());
        store.put("token", b"t-1234").unwrap();
        assert_eq!(store.get("token").unwrap().unwrap(), b"t-1234");
        // 覆盖
        store.put("token", b"t-5678").unwrap();
        assert_eq!(store.get("token").unwrap().unwrap(), b"t-5678");
        // 磁盘上是密文，非明文
        let raw = std::fs::read(store.key_file("token").unwrap()).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"t-5678"));
    }

    #[test]
    fn key_validation() {
        let store = DpapiSecureStore::new(tmp_dir("kv"));
        assert!(store.key_file("").is_err());
        assert!(store.key_file("a/b").is_err());
        assert!(store.key_file("a\\b").is_err());
        assert!(store.key_file("a.b").is_err());
        assert!(store.key_file("ok_key-1").is_ok());
    }
}
