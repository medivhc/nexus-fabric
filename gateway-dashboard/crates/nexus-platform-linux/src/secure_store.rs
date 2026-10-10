//! Linux SecureStore：`/etc/machine-id` 派生密钥的 AEAD 文件存储。
//!
//! 边界（PRODUCT §12.30）：
//! - 密钥派生与 NEXSEC1 记录格式复用 `nexus-platform::secure_store`（纯逻辑）；
//! - 本模块只做平台适配：读 `/etc/machine-id`、文件读写、0600 权限；
//! - machine-id 缺失/非法 → `Unavailable` / `Invalid`（结构化降级，不静默）。

use nexus_platform::{PlatformError, SecureStore};
use std::path::{Path, PathBuf};

/// 后端标识。
pub const BACKEND: &str = "file";

/// machine-id 系统路径（Linux 标准）。
pub const MACHINE_ID_PATH: &str = "/etc/machine-id";

/// 键 → 文件名（纯函数）：拒绝空键与路径分隔符，防目录穿越。
fn key_file(dir: &Path, key: &str) -> Result<PathBuf, PlatformError> {
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
    Ok(dir.join(format!("{key}.nexsec")))
}

/// 读取并解析 machine-id，派生 32 字节密钥。
///
/// 文件缺失/读取失败 → `Unavailable`（平台能力缺失）；内容非法 → `Invalid`。
pub fn derive_key_from_machine_id() -> Result<[u8; 32], PlatformError> {
    let raw = std::fs::read_to_string(MACHINE_ID_PATH).map_err(|e| PlatformError::Unavailable {
        capability: format!("machine-id ({}): {e}", MACHINE_ID_PATH),
    })?;
    let mid = nexus_platform::secure_store::parse_machine_id(&raw)?;
    nexus_platform::secure_store::derive_key(&mid)
}

/// machine-id 存在且可解析 → 能力可用。
#[must_use]
pub fn secure_store_available() -> bool {
    derive_key_from_machine_id().is_ok()
}

/// machine-id 派生密钥的 AEAD 文件存储：每个键一个密文文件（`<dir>/<key>.nexsec`）。
///
/// `get` 缺失键 → `Ok(None)`；`put` 幂等覆盖；文件权限 0600（仅当前用户）。
/// 键校验与 `DpapiSecureStore`（Windows）一致，跨平台语义对齐。
pub struct FileSecureStore {
    dir: PathBuf,
}

impl FileSecureStore {
    /// 创建指向目录的 file store（目录不存在时懒创建）。
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// 本 store 使用的密钥（每次调用重新派生；密钥不落盘）。
    fn key(&self) -> Result<[u8; 32], PlatformError> {
        derive_key_from_machine_id()
    }
}

impl SecureStore for FileSecureStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        let path = key_file(&self.dir, key)?;
        let Ok(cipher) = std::fs::read(&path) else {
            return Ok(None);
        };
        let k = self.key()?;
        nexus_platform::secure_store::decrypt_record(&k, &cipher).map(Some)
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), PlatformError> {
        let path = key_file(&self.dir, key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| PlatformError::Io {
                operation: "secure store mkdir".into(),
                message: e.to_string(),
            })?;
        }
        let k = self.key()?;
        let record = nexus_platform::secure_store::encrypt_record(&k, value)?;
        std::fs::write(&path, &record).map_err(|e| PlatformError::Io {
            operation: "secure store write".into(),
            message: e.to_string(),
        })?;
        // 0600：仅当前用户可读写（平台语义，不依赖 umask）。
        set_0600(&path)?;
        Ok(())
    }
}

/// 把文件权限收紧为 0600（Unix）。非 Unix 宿主（仅编译期）为 no-op：
/// crate 目标是 Linux，host 构建不落盘真实状态。
#[cfg(unix)]
fn set_0600(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        PlatformError::Io {
            operation: "secure store chmod".into(),
            message: e.to_string(),
        }
    })
}

#[cfg(not(unix))]
fn set_0600(_path: &Path) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 纯逻辑测试不依赖真实 /etc/machine-id：直接用 nexus-platform 纯函数验证
    /// 密钥派生与记录格式（真实文件路径/权限走 E5）。
    #[test]
    fn pure_core_roundtrip_via_platform() {
        use nexus_platform::secure_store::{
            decrypt_record, derive_key, encrypt_record, parse_machine_id,
        };
        let mid = parse_machine_id("0123456789abcdef0123456789abcdef").unwrap();
        let key = derive_key(&mid).unwrap();
        let rec = encrypt_record(&key, b"file-store-secret").unwrap();
        assert_eq!(decrypt_record(&key, &rec).unwrap(), b"file-store-secret");
        assert!(rec.starts_with(b"NEXSEC1"));
    }

    #[test]
    fn key_file_validation() {
        let dir = PathBuf::from("/tmp");
        assert!(key_file(&dir, "").is_err());
        assert!(key_file(&dir, "a/b").is_err());
        assert!(key_file(&dir, "a\\b").is_err());
        assert!(key_file(&dir, "a.b").is_err());
        assert!(key_file(&dir, "ok_key-1").is_ok());
    }

    #[test]
    fn machine_id_availability_is_structured() {
        // 真实环境可能缺失 machine-id：断言返回类型化错误而非 panic。
        match derive_key_from_machine_id() {
            Ok(_) => assert!(secure_store_available()),
            Err(PlatformError::Unavailable { .. }) => assert!(!secure_store_available()),
            Err(e) => panic!("unexpected error type: {e:?}"),
        }
    }
}
