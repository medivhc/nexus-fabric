//! 文件 KV 持久化（`FileKvStore`，N2 P0-1 持久基座）。
//!
//! 定位：小体量键值状态（节点身份、grant 表快照、审计日志）的 crash-consistent
//! 持久化。**不碰** `ContentStore` / FNV-1a（被冻结 MODULE invariant 引用）。
//!
//! 写语义（照抄 `fs.rs::atomic_write` 既有模式；`schedule_cli.rs` 的 tmp+rename
//! 在此加强为 tmp + fsync(file) + rename + fsync(dir)）：
//! - `put`：同目录临时文件（`create_new`，防并发覆盖）→ 写全 → `sync_all`
//!   → 原子 `rename` → 目录 `sync_all`。进程中途崩溃只留下孤儿 tmp 文件，
//!   不留下截断的目标文件（下次 `open`/`put` 可清理孤儿 tmp）。
//! - `journal_append`：write-ahead 日志，`[len:u32 LE][payload]` 追加 + fsync，
//!   返回单调 seq。boot 时 `journal_replay` 按序重放；尾部撕裂（crash 写一半）
//!   直接报错 `TornJournalTail`（fail-closed，不静默丢弃），调用方显式
//!   `journal_discard_torn_tail` 后才能继续。
//!
//! 键编码：文件名安全子集 `[A-Za-z0-9._-]` 原样保留，其余字节 `%XX` 转义
//! （大写 hex），可逆；`list` 返回解码后的原始键。空键 / >256 字节拒绝。

use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// 临时文件名前缀（`list` 与重放时跳过）。
const TMP_PREFIX: &str = ".tmp-";
/// journal 文件名。
const JOURNAL_NAME: &str = "journal.log";
/// 键最大字节数。
const MAX_KEY_BYTES: usize = 256;

/// 文件 KV 错误（结构化，不吞因果）。
#[derive(Debug)]
pub enum StorageError {
    /// I/O 失败（携带路径与原因）。
    Io { path: PathBuf, message: String },
    /// 非法键（空 / 超长 / 解码失败）。
    InvalidKey(String),
    /// 数据损坏（journal 记录长度越界等；不静默丢弃）。
    Corrupt { path: PathBuf, reason: String },
    /// journal 尾部撕裂（crash 写一半）；需显式丢弃后继续。
    TornJournalTail { path: PathBuf },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, message } => {
                write!(f, "storage io error at {}: {message}", path.display())
            }
            Self::InvalidKey(k) => write!(f, "invalid storage key: {k:?}"),
            Self::Corrupt { path, reason } => {
                write!(f, "corrupt data at {}: {reason}", path.display())
            }
            Self::TornJournalTail { path } => write!(
                f,
                "torn journal tail at {} (crash mid-append); discard explicitly",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StorageError {}

/// 文件 KV 存储：`<dir>/` 下每个键一个文件。
#[derive(Debug)]
pub struct FileKvStore {
    dir: PathBuf,
    tmp_seq: AtomicU64,
}

impl FileKvStore {
    /// 打开（不存在则创建）KV 目录。
    ///
    /// 目录权限由调用方按需收紧（如节点身份目录 0700；本 crate 为 portable-core
    /// 仅 std，不做平台权限调用）。
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        std::fs::create_dir_all(dir).map_err(|e| StorageError::Io {
            path: dir.to_path_buf(),
            message: format!("create kv dir: {e}"),
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            tmp_seq: AtomicU64::new(0),
        })
    }

    /// KV 根目录。
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 键对应的存储文件名（转义后；`None` = 非法键）。
    ///
    /// 供调用方在平台侧做文件级权限收紧等元操作（本 crate 仅 std）。
    #[must_use]
    pub fn file_name_for(key: &str) -> Option<String> {
        encode_key(key)
    }

    /// 键 → 文件名（转义）；非法键返回 `None`。
    fn path_of(&self, key: &str) -> Option<PathBuf> {
        let enc = encode_key(key)?;
        Some(self.dir.join(enc))
    }

    /// 原子写：tmp(create_new) + write + fsync(file) + rename + fsync(dir)。
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let target = self
            .path_of(key)
            .ok_or_else(|| StorageError::InvalidKey(key.to_string()))?;
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!("{TMP_PREFIX}{}-{seq}", std::process::id()));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| StorageError::Io {
                    path: tmp.clone(),
                    message: format!("create tmp file: {e}"),
                })?;
            f.write_all(value).map_err(|e| StorageError::Io {
                path: tmp.clone(),
                message: format!("write tmp file: {e}"),
            })?;
            f.sync_all().map_err(|e| StorageError::Io {
                path: tmp.clone(),
                message: format!("fsync tmp file: {e}"),
            })?;
        }
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            StorageError::Io {
                path: target.clone(),
                message: format!("rename tmp into place: {e}"),
            }
        })?;
        // 目录 fsync：保证 rename 本身 crash 后可见。
        if let Ok(dir_fd) = OpenOptions::new().read(true).open(&self.dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    }

    /// 读键；不存在 → `Ok(None)`。
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self
            .path_of(key)
            .ok_or_else(|| StorageError::InvalidKey(key.to_string()))?;
        match std::fs::read(&path) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::Io {
                path,
                message: format!("read: {e}"),
            }),
        }
    }

    /// 删键；不存在 → `Ok(())`（幂等）。
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self
            .path_of(key)
            .ok_or_else(|| StorageError::InvalidKey(key.to_string()))?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io {
                path,
                message: format!("delete: {e}"),
            }),
        }
    }

    /// 列出全部键（解码后；跳过 `.tmp-*` 孤儿文件）。
    pub fn list(&self) -> Result<Vec<String>, StorageError> {
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&self.dir).map_err(|e| StorageError::Io {
            path: self.dir.clone(),
            message: format!("list dir: {e}"),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| StorageError::Io {
                path: self.dir.clone(),
                message: format!("read dir entry: {e}"),
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(TMP_PREFIX) || name == JOURNAL_NAME {
                continue;
            }
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                keys.push(decode_key(&name).ok_or_else(|| {
                    StorageError::InvalidKey(format!("undecodable file name: {name}"))
                })?);
            }
        }
        keys.sort();
        Ok(keys)
    }

    /// journal 路径。
    fn journal_path(&self) -> PathBuf {
        self.dir.join(JOURNAL_NAME)
    }

    /// write-ahead 追加：`[len:u32 LE][payload]` + fsync，返回单调 seq
    /// （seq = 记录在文件中的起始偏移；重放顺序即追加顺序）。
    pub fn journal_append(&self, payload: &[u8]) -> Result<u64, StorageError> {
        let path = self.journal_path();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| StorageError::Io {
                path: path.clone(),
                message: format!("open journal: {e}"),
            })?;
        let seq = f
            .seek(std::io::SeekFrom::End(0))
            .map_err(|e| StorageError::Io {
                path: path.clone(),
                message: format!("seek journal end: {e}"),
            })?;
        let len = u32::try_from(payload.len()).map_err(|_| {
            StorageError::InvalidKey(format!("journal payload too large: {}", payload.len()))
        })?;
        f.write_all(&len.to_le_bytes())
            .map_err(|e| StorageError::Io {
                path: path.clone(),
                message: format!("write journal len: {e}"),
            })?;
        f.write_all(payload).map_err(|e| StorageError::Io {
            path: path.clone(),
            message: format!("write journal payload: {e}"),
        })?;
        f.sync_all().map_err(|e| StorageError::Io {
            path: path.clone(),
            message: format!("fsync journal: {e}"),
        })?;
        Ok(seq)
    }

    /// boot 重放：按序返回全部完整记录。
    ///
    /// 尾部撕裂（长度头不完整 / payload 不足）→ `Err(TornJournalTail)`，
    /// fail-closed；调用方检查后可用 `journal_discard_torn_tail` 显式丢弃。
    pub fn journal_replay(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let path = self.journal_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(StorageError::Io {
                    path,
                    message: format!("read journal: {e}"),
                });
            }
        };
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            let rest = &bytes[off..];
            if rest.len() < 4 {
                return Err(StorageError::TornJournalTail { path });
            }
            let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > 64 * 1024 * 1024 {
                return Err(StorageError::Corrupt {
                    path,
                    reason: format!("journal record len out of range: {len}"),
                });
            }
            if rest.len() < 4 + len {
                return Err(StorageError::TornJournalTail { path });
            }
            out.push(rest[4..4 + len].to_vec());
            off += 4 + len;
        }
        Ok(out)
    }

    /// 显式丢弃撕裂尾部（reconciliation 路径调用；审计留痕由调用方负责）。
    pub fn journal_discard_torn_tail(&self) -> Result<(), StorageError> {
        let path = self.journal_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(StorageError::Io {
                    path,
                    message: format!("read journal: {e}"),
                });
            }
        };
        let mut off = 0usize;
        while off < bytes.len() {
            let rest = &bytes[off..];
            if rest.len() < 4 {
                break;
            }
            let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > 64 * 1024 * 1024 || rest.len() < 4 + len {
                break;
            }
            off += 4 + len;
        }
        if off == bytes.len() {
            return Ok(()); // 无撕裂，无事可做。
        }
        // 截断到最后一条完整记录（原子：tmp + fsync + rename）。
        let tmp = self
            .dir
            .join(format!("{TMP_PREFIX}journal-{}", std::process::id()));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| StorageError::Io {
                    path: tmp.clone(),
                    message: format!("create tmp journal: {e}"),
                })?;
            f.write_all(&bytes[..off]).map_err(|e| StorageError::Io {
                path: tmp.clone(),
                message: format!("write truncated journal: {e}"),
            })?;
            f.sync_all().map_err(|e| StorageError::Io {
                path: tmp.clone(),
                message: format!("fsync tmp journal: {e}"),
            })?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            StorageError::Io {
                path: path.clone(),
                message: format!("rename truncated journal: {e}"),
            }
        })?;
        if let Ok(dir_fd) = OpenOptions::new().read(true).open(&self.dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    }

    /// 清空 journal（调用方已把记录应用到状态之后；幂等）。
    pub fn journal_truncate(&self) -> Result<(), StorageError> {
        let path = self.journal_path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io {
                path,
                message: format!("truncate journal: {e}"),
            }),
        }
    }
}

/// 键编码：`[A-Za-z0-9._-]` 原样，其余字节 `%XX`（大写 hex）；非法 → `None`。
fn encode_key(key: &str) -> Option<String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return None;
    }
    let mut out = String::with_capacity(key.len());
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit(u32::from(b >> 4), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit(u32::from(b & 0x0f), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    // 编码后仍以点开头的文件名（`..` / `.tmp-` 风格）一律拒绝，防目录穿越。
    if out.starts_with('.') {
        return None;
    }
    Some(out)
}

/// 键解码（`encode_key` 的逆）。
fn decode_key(encoded: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(encoded.len());
    let raw = encoded.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len() {
                return None;
            }
            let hi = char::from(raw[i + 1]).to_digit(16)?;
            let lo = char::from(raw[i + 2]).to_digit(16)?;
            bytes.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nexus-kv-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tmpdir("roundtrip");
        let kv = FileKvStore::open(&dir).unwrap();
        assert_eq!(kv.get("node/identity").unwrap(), None);
        kv.put("node/identity", b"{\"a\":1}").unwrap();
        assert_eq!(
            kv.get("node/identity").unwrap(),
            Some(b"{\"a\":1}".to_vec())
        );
        // 覆盖写原子替换。
        kv.put("node/identity", b"v2").unwrap();
        assert_eq!(kv.get("node/identity").unwrap(), Some(b"v2".to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_is_atomic_no_truncated_target() {
        // tmp 文件存在但目标文件永不出现半截内容：put 成功后目标即完整。
        let dir = tmpdir("atomic");
        let kv = FileKvStore::open(&dir).unwrap();
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        kv.put("k", &big).unwrap();
        assert_eq!(kv.get("k").unwrap().unwrap().len(), big.len());
        // 孤儿 tmp 不污染 list。
        assert_eq!(kv.list().unwrap(), vec!["k".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_encoding_roundtrip_and_traversal_rejected() {
        assert_eq!(encode_key("a/b:c"), Some("a%2Fb%3Ac".to_string()));
        assert_eq!(decode_key("a%2Fb%3Ac"), Some("a/b:c".to_string()));
        assert!(encode_key("").is_none());
        assert!(encode_key("../evil").is_none());
        assert!(encode_key(".hidden").is_none());
        assert!(encode_key(&"x".repeat(257)).is_none());
        let dir = tmpdir("keys");
        let kv = FileKvStore::open(&dir).unwrap();
        assert!(matches!(
            kv.put("../evil", b"x"),
            Err(StorageError::InvalidKey(_))
        ));
        assert!(matches!(kv.get(""), Err(StorageError::InvalidKey(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tmpdir("delete");
        let kv = FileKvStore::open(&dir).unwrap();
        kv.delete("nope").unwrap();
        kv.put("k", b"v").unwrap();
        kv.delete("k").unwrap();
        assert_eq!(kv.get("k").unwrap(), None);
        kv.delete("k").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_append_replay_truncate() {
        let dir = tmpdir("journal");
        let kv = FileKvStore::open(&dir).unwrap();
        // 空 journal 重放为空（boot 首次）。
        assert!(kv.journal_replay().unwrap().is_empty());
        let s0 = kv.journal_append(b"rec-1").unwrap();
        let s1 = kv.journal_append(b"rec-2").unwrap();
        assert!(s1 > s0);
        // 新 open 模拟重启：记录仍在。
        let kv2 = FileKvStore::open(&dir).unwrap();
        let recs = kv2.journal_replay().unwrap();
        assert_eq!(recs, vec![b"rec-1".to_vec(), b"rec-2".to_vec()]);
        kv2.journal_truncate().unwrap();
        assert!(kv2.journal_replay().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_torn_tail_fails_closed_and_discards_explicitly() {
        let dir = tmpdir("torn");
        let kv = FileKvStore::open(&dir).unwrap();
        kv.journal_append(b"good").unwrap();
        // 模拟 crash 写一半：手写一个不完整的尾部。
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join(JOURNAL_NAME))
                .unwrap();
            f.write_all(&[0x05, 0x00]).unwrap(); // len 头只有 2 字节
        }
        assert!(matches!(
            kv.journal_replay(),
            Err(StorageError::TornJournalTail { .. })
        ));
        // 显式丢弃后，完整前缀可重放。
        kv.journal_discard_torn_tail().unwrap();
        assert_eq!(kv.journal_replay().unwrap(), vec![b"good".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_survives_reopen_before_truncate() {
        // write-ahead 语义：append 已 fsync，进程"重启"后记录不丢。
        let dir = tmpdir("reopen");
        {
            let kv = FileKvStore::open(&dir).unwrap();
            kv.journal_append(b"audit-1").unwrap();
        }
        let kv = FileKvStore::open(&dir).unwrap();
        assert_eq!(kv.journal_replay().unwrap(), vec![b"audit-1".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
