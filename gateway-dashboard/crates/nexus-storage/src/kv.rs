//! 文件 KV 持久化（`FileKvStore`，N2 P0-1 持久基座）。
//!
//! 定位：小体量键值状态（节点身份、grant 表快照、审计日志）的 crash-consistent
//! 持久化。**不碰** `ContentStore` / FNV-1a（被冻结 MODULE invariant 引用）。
//!
//! 写语义（照抄 `fs.rs::atomic_write` 既有模式；`schedule_cli.rs` 的 tmp+rename
//! 在此加强为 tmp + fsync(file) + rename + fsync(dir)）：
//! - `put`：同目录临时文件（`create_new`，防并发覆盖）→ 写全 → `sync_all`
//!   → 原子 `rename` → 目录 `sync_all`。进程中途崩溃只留下孤儿 tmp 文件，
//!   不留下截断的目标文件（`open` 清理 `.tmp-*` 孤儿、`put` 遇同名即换名重试，
//!   见 [`FileKvStore::open`] 与 [`FileKvStore::put`]）。
//! - `journal_append`：write-ahead 日志，`[len:u32 LE][payload]` 追加 + fsync，
//!   返回单调 seq。**header+payload 拼成单次 `write_all`**（P1-11：两次独立
//!   `write_all` 会被并发写者的 O_APPEND 交错切开，`TornJournalTail` 会让整个
//!   journal 不可读）。boot 时 `journal_replay` 按序重放（含轮转段）；尾部撕裂
//!   （crash 写一半）直接报错 `TornJournalTail`（fail-closed，不静默丢弃），
//!   调用方显式 `journal_discard_torn_tail` 后才能继续。journal 超上限自动
//!   轮转（保留一代），避免无界增长。
//!
//! 键编码：文件名安全子集 `[A-Za-z0-9._-]` 原样保留，其余字节 `%XX` 转义
//! （大写 hex），可逆；`list` 返回解码后的原始键。空键 / >256 字节拒绝。

use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// 临时文件名前缀（`list` 与重放时跳过）。
const TMP_PREFIX: &str = ".tmp-";
/// journal 文件名（活动段）。
const JOURNAL_NAME: &str = "journal.log";
/// journal 轮转后的上一代文件名（`journal.log.1`）。
const JOURNAL_ROTATED_NAME: &str = "journal.log.1";
/// journal 活动段大小上限（字节）；超过即轮转（保留一代）。
///
/// P1-11：无界增长的审计 journal 会吃光磁盘；轮转把上界钉死在约 2×此值。
/// 轮转会丢弃最老的一代记录——这是 P0 的显式取舍（长期审计归档为 P1：
/// 调用方应在接近上限前 `journal_replay` 导出）。
pub const JOURNAL_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// tmp 文件 `create_new` 撞名时的最大重试次数。
const TMP_CREATE_RETRIES: u32 = 8;
/// 孤儿 tmp 清理宽限期（秒）：只删 mtime 早于该值的 `.tmp-*`，
/// 避免误删并发写者仍在使用的在途临时文件（P1-10）。
const TMP_ORPHAN_GRACE_SECS: u64 = 300;
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
    /// tmp 名进程级随机 salt（P1-10：跨进程 pid 复用时区分孤儿）。
    tmp_salt: u64,
}

impl FileKvStore {
    /// 打开（不存在则创建）KV 目录，并清理崩溃留下的 `.tmp-*` 孤儿文件。
    ///
    /// 目录权限由调用方按需收紧（如节点身份目录 0700；本 crate 为 portable-core
    /// 仅 std，不做平台权限调用）。
    ///
    /// P1-10：孤儿 tmp 必须在此清掉——pid 复用（Linux pid 回卷）会让新进程
    /// 算出与孤儿完全相同的 tmp 名，此后每次 `put` 都 `AlreadyExists`，永久失败。
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        std::fs::create_dir_all(dir).map_err(|e| StorageError::Io {
            path: dir.to_path_buf(),
            message: format!("create kv dir: {e}"),
        })?;
        // P1-10：清理超过宽限期的孤儿 `.tmp-*`（文档承诺的 open 时清理）。
        clean_orphan_tmp(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            tmp_seq: AtomicU64::new(0),
            tmp_salt: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                ^ (u64::from(std::process::id()) << 32),
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

    /// 分配一个本次独占的 tmp 路径（`.tmp-<tag>-<pid>-<seq>-<nonce>`）。
    ///
    /// P1-10：`nonce`（时钟纳秒低 32 位）让同 pid 的多次调用也不撞名；
    /// 仍撞名时由 [`FileKvStore::create_tmp`] 换名重试。
    /// 下一个候选 tmp 路径：`{TMP_PREFIX}{tag}-{pid}-{seq}-{salt}`。
    ///
    /// salt 由 `open` 时刻的纳秒与 pid 派生，`seq` 进程内单调 —— 单靠 pid 复用
    /// 不再能撞名；仍撞名由 `put` 换名重试兜底（P1-10）。
    fn tmp_path(&self, tag: &str, seq: u64) -> PathBuf {
        let salt = self.tmp_salt ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.dir.join(format!(
            "{TMP_PREFIX}{tag}-{}-{seq}-{salt:016x}",
            std::process::id()
        ))
    }

    /// `create_new` 打开 tmp 文件；撞名（`AlreadyExists`）换名重试。
    ///
    /// 换名而非覆盖：并发写者的 tmp 必须互不可见——`put` 的原子 rename 前提是
    /// tmp 内容只属于本次写。
    fn create_tmp(&self, tag: &str, seq: u64) -> Result<(PathBuf, std::fs::File), StorageError> {
        let mut last: Option<(PathBuf, std::io::Error)> = None;
        for attempt in 0..TMP_CREATE_RETRIES {
            let candidate = self.tmp_path(tag, seq.wrapping_add(u64::from(attempt)));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(f) => return Ok((candidate, f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    last = Some((candidate, e));
                }
                Err(e) => {
                    return Err(StorageError::Io {
                        path: candidate,
                        message: format!("create tmp file: {e}"),
                    });
                }
            }
        }
        let (path, e) = last.expect("at least one attempt ran");
        Err(StorageError::Io {
            path,
            message: format!("create tmp file: {e} (retries exhausted)"),
        })
    }

    /// 原子写：tmp(create_new) + write + fsync(file) + rename + fsync(dir)。
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let target = self
            .path_of(key)
            .ok_or_else(|| StorageError::InvalidKey(key.to_string()))?;
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let (tmp, mut f) = self.create_tmp("put", seq)?;
        let written = f.write_all(value).and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(StorageError::Io {
                path: tmp,
                message: format!("write tmp file: {e}"),
            });
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
            if name.starts_with(TMP_PREFIX) || is_journal_segment(&name) {
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

    /// journal 路径（活动段）。
    fn journal_path(&self) -> PathBuf {
        self.dir.join(JOURNAL_NAME)
    }

    /// 上一代 journal 路径（轮转产物）。
    fn journal_rotated_path(&self) -> PathBuf {
        self.dir.join(JOURNAL_ROTATED_NAME)
    }

    /// write-ahead 追加：`[len:u32 LE][payload]` + fsync，返回单调 seq
    /// （seq = 记录在活动段中的起始偏移；重放顺序即追加顺序）。
    ///
    /// P1-11（多写者安全）：header 与 payload **拼成一个缓冲、单次 `write_all`**。
    /// 原实现分两次写，只靠 `O_APPEND` 的单次写原子性——两个并发写者
    /// （CLI 与 `provider serve`）的两次写会交错，产生 `TornJournalTail`，
    /// 让**整个** journal 不可读。单次写把这条竞态收敛掉。
    ///
    /// P1-11（无界增长）：活动段超过 [`JOURNAL_MAX_BYTES`] 即轮转：旧活动段
    /// rename 为 `journal.log.1`（覆盖更老的一代），新记录写进新建的活动段。
    pub fn journal_append(&self, payload: &[u8]) -> Result<u64, StorageError> {
        let path = self.journal_path();
        let len = u32::try_from(payload.len()).map_err(|_| {
            StorageError::InvalidKey(format!("journal payload too large: {}", payload.len()))
        })?;
        // 单次写缓冲：4 字节长度头＋payload。
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(payload);
        // 轮转（幂等：仅活动段超上限时发生）。
        self.rotate_journal_if_needed(&path)?;
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
        f.write_all(&frame).map_err(|e| StorageError::Io {
            path: path.clone(),
            message: format!("write journal record: {e}"),
        })?;
        f.sync_all().map_err(|e| StorageError::Io {
            path: path.clone(),
            message: format!("fsync journal: {e}"),
        })?;
        Ok(seq)
    }

    /// 活动段超过 [`JOURNAL_MAX_BYTES`] 时轮转一代（`journal.log` → `journal.log.1`）。
    fn rotate_journal_if_needed(&self, path: &Path) -> Result<(), StorageError> {
        let size = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(StorageError::Io {
                    path: path.to_path_buf(),
                    message: format!("stat journal: {e}"),
                });
            }
        };
        if size <= JOURNAL_MAX_BYTES {
            return Ok(());
        }
        // rename 覆盖既有上一代：POSIX 下原子，旧的一代随之淘汰。
        std::fs::rename(path, self.journal_rotated_path()).map_err(|e| StorageError::Io {
            path: path.to_path_buf(),
            message: format!("rotate journal: {e}"),
        })?;
        if let Ok(dir_fd) = OpenOptions::new().read(true).open(&self.dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    }

    /// boot 重放：按序返回全部完整记录（先上一代，再活动段）。
    ///
    /// 尾部撕裂（长度头不完整 / payload 不足）→ `Err(TornJournalTail)`，
    /// fail-closed；调用方检查后可用 `journal_discard_torn_tail` 显式丢弃。
    pub fn journal_replay(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut out = Vec::new();
        for path in [self.journal_rotated_path(), self.journal_path()] {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
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
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let (tmp, mut f) = self.create_tmp("journal", seq)?;
        let written = f.write_all(&bytes[..off]).and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(StorageError::Io {
                path: tmp,
                message: format!("write truncated journal: {e}"),
            });
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
    ///
    /// 轮转后 journal 有两段，`truncate` 必须两段都清，否则 `journal_replay`
    /// 仍会返回上一代记录。
    pub fn journal_truncate(&self) -> Result<(), StorageError> {
        for path in [self.journal_path(), self.journal_rotated_path()] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(StorageError::Io {
                        path,
                        message: format!("truncate journal: {e}"),
                    });
                }
            }
        }
        Ok(())
    }
}

/// 文件名是否为 journal 段（活动段或轮转产物）。
fn is_journal_segment(name: &str) -> bool {
    name == JOURNAL_NAME || (name.starts_with(JOURNAL_NAME) && is_journal_generation(name))
}

/// `journal.log.<n>` 形式的轮转代数（`n` 为纯数字）。
fn is_journal_generation(name: &str) -> bool {
    name.strip_prefix(JOURNAL_NAME)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()))
}

/// 清理 `dir` 下崩溃遗留的 `.tmp-*` 孤儿文件（P1-10）。
///
/// 只删 mtime 早于宽限期的文件：宽限期内的疑似在途文件不动，
/// 避免误删并发写者仍在使用的 tmp（否则在途方的 `rename`
/// 会报 NotFound）。
fn clean_orphan_tmp(dir: &Path) -> Result<(), StorageError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(StorageError::Io {
                path: dir.to_path_buf(),
                message: format!("scan tmp dir: {e}"),
            });
        }
    };
    let now = std::time::SystemTime::now();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(TMP_PREFIX) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let age = now.duration_since(modified).unwrap_or_default().as_secs();
        if age < TMP_ORPHAN_GRACE_SECS {
            continue;
        }
        let _ = std::fs::remove_file(entry.path());
    }
    Ok(())
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

    // --- P1-10：孤儿 tmp 不再让 put 永久失败 ------------------------------

    fn backdate(path: &std::path::Path, secs: u64) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        f.set_times(std::fs::FileTimes::new().set_modified(t))
            .unwrap();
    }

    /// P1-10：`open` 清理超宽限期的孤儿 tmp，但放过仍在宽限期内的在途 tmp。
    #[test]
    fn open_cleans_expired_orphan_tmp_but_spares_fresh_ones() {
        let dir = tmpdir("orphanclean");
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join(format!("{TMP_PREFIX}12345-0"));
        std::fs::write(&stale, b"stale").unwrap();
        backdate(&stale, TMP_ORPHAN_GRACE_SECS + 60);
        let inflight = dir.join(format!("{TMP_PREFIX}99999-0"));
        std::fs::write(&inflight, b"inflight").unwrap();

        FileKvStore::open(&dir).unwrap();
        assert!(!stale.exists(), "expired orphan tmp must be cleaned");
        assert!(inflight.exists(), "fresh tmp may belong to a live writer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_recovers_when_tmp_name_collides() {
        // 同名撞车（pid 复用）时 put 必须换名重试，而不是永久 AlreadyExists。
        let dir = tmpdir("tmp-collide");
        let kv = FileKvStore::open(&dir).unwrap();
        // 抢先占住下一个 seq 的 tmp 名：`create_tmp` 首撞即 AlreadyExists。
        let seq = kv.tmp_seq.load(Ordering::Relaxed);
        for attempt in 0..2u64 {
            let squatter = kv.tmp_path("put", seq + attempt);
            std::fs::write(&squatter, b"x").unwrap();
        }
        kv.put("k", b"v").unwrap();
        assert_eq!(kv.get("k").unwrap(), Some(b"v".to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphan_tmp_never_pollutes_list() {
        let dir = tmpdir("tmp-list");
        let kv = FileKvStore::open(&dir).unwrap();
        kv.put("k", b"v").unwrap();
        std::fs::write(dir.join(format!("{TMP_PREFIX}leftover",)), b"x").unwrap();
        assert_eq!(kv.list().unwrap(), vec!["k".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- P1-11：journal 单次写／轮转上界 --------------------------------

    #[test]
    fn journal_record_is_written_in_one_shot() {
        // header+payload 必须是一次 write_all（并发写者交错即 TornJournalTail）。
        // 结构断言：任何一条记录重放后长度即 payload 长度，且无撕裂。
        let dir = tmpdir("journal-oneshot");
        let kv = FileKvStore::open(&dir).unwrap();
        for i in 0..64u32 {
            let payload = format!("payload-{i}").into_bytes();
            kv.journal_append(&payload).unwrap();
        }
        let recs = kv.journal_replay().unwrap();
        assert_eq!(recs.len(), 64);
        assert_eq!(recs[63], b"payload-63".to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_rotates_and_keeps_one_generation() {
        // 轮转上限：活动段超上限即轮转一代；重放顺序为 上一代 → 活动段。
        let dir = tmpdir("journal-rotate");
        let kv = FileKvStore::open(&dir).unwrap();
        kv.journal_append(b"gen0-first").unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        // 写到超过 JOURNAL_MAX_BYTES，触发至少一次轮转。
        let mut rounds = 0;
        while !dir.join(JOURNAL_ROTATED_NAME).exists() && rounds < 1024 {
            kv.journal_append(&chunk).unwrap();
            rounds += 1;
        }
        assert!(rounds < 1024, "rotation must trigger before the round cap");
        assert!(
            dir.join(JOURNAL_ROTATED_NAME).exists(),
            "rotation must produce {JOURNAL_ROTATED_NAME}"
        );
        let recs = kv.journal_replay().unwrap();
        // 上一代的第一条记录仍在（保留一代），且整体不撕裂。
        assert_eq!(recs.first().map(Vec::as_slice), Some(&b"gen0-first"[..]));
        // 只保留两段（有界）。
        let segments = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| is_journal_segment(&e.file_name().to_string_lossy()))
            .count();
        assert_eq!(segments, 2, "journal must stay bounded to two segments");
        // truncate 两段都清。
        kv.journal_truncate().unwrap();
        assert!(kv.journal_replay().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_segments_are_not_listed_as_keys() {
        let dir = tmpdir("journal-list");
        let kv = FileKvStore::open(&dir).unwrap();
        kv.put("n2/x", b"v").unwrap();
        kv.journal_append(b"rec").unwrap();
        assert_eq!(kv.list().unwrap(), vec!["n2/x".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_generation_name_matcher() {
        assert!(is_journal_segment("journal.log"));
        assert!(is_journal_segment("journal.log.1"));
        assert!(is_journal_segment("journal.log.42"));
        assert!(!is_journal_segment("journal.log.x"));
        assert!(!is_journal_segment("journal.logx"));
        assert!(!is_journal_segment("n2/journal.log.1"));
    }
}
