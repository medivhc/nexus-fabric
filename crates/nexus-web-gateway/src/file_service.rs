//! Node-side file engine for the Nexus Web Gateway (`PRODUCT.md#18-gateway-file-service`).
//!
//! Contract: MODULE.md invariants **G12-G21**. This module is the *engine*, not
//! the wire: WebRTC framing, channel negotiation and DataChannel dispatch are
//! deliberately absent here (they are M2 in `docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md`
//! §11), which is what lets the whole security surface be built and probed
//! without touching the signalling code path.
//!
//! Design rules that are load-bearing for the contract, restated because they
//! are easy to regress:
//!
//! - **std-only, `#![forbid(unsafe_code)]`** (crate-wide): there is no
//!   `O_NOFOLLOW`, no `dev/ino` handle identity on Windows, and no `libc`.
//!   Path safety therefore rests on *componentwise* `symlink_metadata` plus a
//!   **post-operation re-resolve**, and the residual race window is documented
//!   rather than hidden (G13, and the Windows B-level note in `PRODUCT.md` §18.3).
//! - **No panics on externally controllable input**: every offset/length
//!   computation is `checked_*`, every backend call returns `FileError`
//!   (G20). The release profile is `panic = "abort"`, so `catch_unwind` is not
//!   an available safety net — the code must be panic-free by construction.
//! - **Nothing self-declares compliance**: each invariant that the E4 probe
//!   asserts is measurable from real state (handle counters, throttle table
//!   length, contiguous-prefix accounting, drop counters), and the probe runs a
//!   *differential* naive path where a "resolve once / ack per chunk / no
//!   throttle" implementation would pass for the wrong reason.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

/// Machine-readable failure codes. These are the strings the product contract
/// promises (`OUTPUT_EXISTS`, `PAGE_TOO_LARGE`, `QUEUE_FULL`, ...), so they are
/// part of the observable surface and must not drift.
pub mod code {
    pub const CONFIG: &str = "CONFIG_INVALID";
    pub const AUTH_DENIED: &str = "AUTH_DENIED";
    pub const THROTTLED: &str = "THROTTLED";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const OUTSIDE_ROOT: &str = "OUTSIDE_ROOT";
    pub const SYMLINK_ESCAPE: &str = "SYMLINK_ESCAPE";
    pub const NON_CANONICAL_ROOT: &str = "NON_CANONICAL_ROOT";
    pub const READ_ONLY: &str = "READ_ONLY";
    pub const EXISTS: &str = "OUTPUT_EXISTS";
    pub const PAGE_TOO_LARGE: &str = "PAGE_TOO_LARGE";
    pub const TRUNCATED: &str = "TRUNCATED";
    pub const INTEGRITY: &str = "ARTIFACT_INTEGRITY_FAILED";
    pub const QUEUE_FULL: &str = "QUEUE_FULL";
    pub const CAPACITY: &str = "CAPACITY_UNAVAILABLE";
    pub const UNSUPPORTED: &str = "UNSUPPORTED_CAPABILITY";
    pub const OVERFLOW: &str = "OFFSET_OVERFLOW";
    pub const IS_DIR: &str = "IS_DIR";
    pub const IDLE: &str = "IDLE_RECYCLED";
}

/// Typed failure with a stable code (G6/G20: no `unwrap`, no panic path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    pub code: &'static str,
    pub message: String,
}

impl FileError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for FileError {}

pub type FileResult<T> = Result<T, FileError>;

/// All numeric ceilings for one gateway's file surface (G12/G16/G18).
///
/// `validate()` is the fail-closed gate: it enforces the *cross* constraints,
/// not just per-field sanity, because a self-inconsistent table is exactly how
/// V1 shipped a single oversized ack and a per-chunk stream identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLimits {
    /// Bytes per read/upload page.
    pub chunk_bytes: usize,
    /// Hard ceiling on the number of entries in one list page.
    pub max_entries_per_page: usize,
    /// Hard ceiling on the serialized size of one acknowledgement.
    pub max_ack_bytes: usize,
    /// Concurrent file sessions the node side will host.
    pub max_sessions: usize,
    /// Concurrent file sessions one browser peer may hold.
    pub max_browser_sessions: usize,
    /// Open read handles at once (across all sessions).
    pub max_read_handles: usize,
    /// In-flight (unacknowledged) bytes per session.
    pub max_inflight_bytes_per_session: usize,
    /// Declared size ceiling for one upload.
    pub max_upload_bytes: u64,
    /// Bytes the server will **re-read from disk** per stream while verifying a
    /// duplicate/replayed page. Sequential new bytes are hashed as they arrive,
    /// whose cost is already bounded by `max_upload_bytes` — so this budget must
    /// not gate the digest itself, or an artifact larger than the budget could
    /// never be digest-published（评审 WARN：旧实现把它当验证门用）.
    pub max_rehash_bytes_per_stream: u64,
    /// Idle window after which a file session is recycled (G21).
    pub idle_timeout: Duration,
    /// Failed authentications before the principal/source bucket is locked out.
    pub lockout_after: usize,
    /// How long a lockout lasts. A field rather than a hardcoded 60 s so the
    /// expiry path (re-lock after lapse, overflow counter decay) is testable
    /// without sleeping for a minute（评审 r3 R3-NEW-2 要求可验证）.
    pub lockout_window: Duration,
    /// Rows kept in the throttle table. Beyond it a *new* identity gets no row of
    /// its own: its failures accumulate in the overflow counter, which escalates
    /// to the fail-closed global window (G15). Rows are neither merged nor evicted
    /// — a row is dropped once that identity stays quiet for one `lockout_window`
    /// (`Throttle::decay`), which is what stops forged volume from squatting the
    /// table. 旧措辞 "oldest buckets are merged into the global bucket" 从来没有
    /// 对应实现（评审 r7 R7-N-7）。
    pub max_throttle_buckets: usize,
    /// Failures one **transport address** may contribute inside a window before
    /// that address itself is locked (`Throttle::source_locks`). The pair key
    /// (principal, source) means a single peer can otherwise mint
    /// `max_throttle_buckets` distinct principals and spend the whole table's
    /// guessing budget on identities it does not own（评审 r7 整改清单第 3 条 /
    /// r8 R7-N-9：一个源就能占满额度池）。This bounds a peer's **blast radius**,
    /// not the aggregate auth rate — that bound is `max_throttle_buckets ×
    /// lockout_after / lockout_window` and belongs to M2's connection-layer
    /// rate limiting (G15 代价 (3)).
    pub max_failures_per_source: usize,
    /// SCTP `max_buffered_amount` budget shared by the control and file channels.
    pub max_buffered_amount: usize,
}

impl Default for FileLimits {
    fn default() -> Self {
        Self {
            chunk_bytes: 64 * 1024,
            max_entries_per_page: 256,
            max_ack_bytes: 32 * 1024,
            max_sessions: 4,
            max_browser_sessions: 2,
            max_read_handles: 32,
            // 与 max_buffered_amount 同量级：in-flight 与共享发送预算由**同一个
            // 事件**（对端 ack / 传输冲刷）释放，所以高于预算的 per-session 上限
            // 是永远够不到的死配置（评审 WARN：旧默认 1 MiB 配 128 KiB 预算）。
            max_inflight_bytes_per_session: 128 * 1024,
            max_upload_bytes: 2 * 1024 * 1024 * 1024,
            max_rehash_bytes_per_stream: 64 * 1024 * 1024,
            idle_timeout: Duration::from_secs(300),
            lockout_after: 5,
            lockout_window: Duration::from_secs(60),
            max_throttle_buckets: 1024,
            max_failures_per_source: 40,
            max_buffered_amount: 128 * 1024,
        }
    }
}

impl FileLimits {
    /// Fail-closed cross validation (G12). Any violation is a startup error.
    pub fn validate(&self) -> FileResult<()> {
        if self.chunk_bytes == 0
            || self.max_entries_per_page == 0
            || self.max_ack_bytes == 0
            || self.max_sessions == 0
            || self.max_browser_sessions == 0
            || self.max_read_handles == 0
            || self.max_buffered_amount == 0
            || self.lockout_after == 0
            || self.max_throttle_buckets == 0
            || self.max_failures_per_source == 0
        {
            return Err(FileError::new(
                code::CONFIG,
                "no limit may be zero: a zero ceiling silently disables its gate",
            ));
        }
        // 时长与 u64 上限同样受这条规则约束（评审 r4 R4-NEW-1）：
        // `lockout_window = 0` 时每次锁定在写入的那一刻就已过期，全局窗口又只在
        // 锁表满时才升级，于是**每个错令牌都能走到常数时间比较**——实测比较次数
        // 从 5/200 变成 200/200，G15 的"有界尝试"变成纸面话。
        // `idle_timeout = 0` 会让会话刚建立就被回收；`max_upload_bytes = 0` 与
        // `max_rehash_bytes_per_stream = 0` 则是"声明了上限但任何操作都超"的死配置。
        if self.lockout_window.is_zero() {
            return Err(FileError::new(
                code::CONFIG,
                "lockout_window must not be zero: a zero lockout expires on insert and disables throttling",
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(FileError::new(
                code::CONFIG,
                "idle_timeout must not be zero: every session would be recycled the moment it is created",
            ));
        }
        if self.max_upload_bytes == 0 || self.max_rehash_bytes_per_stream == 0 {
            return Err(FileError::new(
                code::CONFIG,
                "no limit may be zero: a zero ceiling silently disables its gate",
            ));
        }
        // 高边同样要封（评审 r5 R5-W-2：同一片刚在 config.rs 里给 max_terminals
        // 补了上界，却没封自己新加的两个时长）。时长参与 `Instant + Duration`，
        // 一个病态大值不是"更宽松"，而是把锁死/回收推到时钟边界之外；
        // 数值型上限（上传大小、回读预算）本身没有这种后果，仍只封低边。
        const MAX_WINDOW_SECS: u64 = 24 * 3600;
        if self.lockout_window > Duration::from_secs(MAX_WINDOW_SECS) {
            return Err(FileError::new(
                code::CONFIG,
                "lockout_window must be <= 24h: an unbounded window cannot be represented in clock arithmetic",
            ));
        }
        if self.idle_timeout > Duration::from_secs(MAX_WINDOW_SECS) {
            return Err(FileError::new(
                code::CONFIG,
                "idle_timeout must be <= 24h: an unbounded window cannot be represented in clock arithmetic",
            ));
        }
        // 计费配额要配对：`list` 现在按 `ack_bytes` 过账，所以一条完整 ack 必须
        // 放得进单会话在途上限，否则每个 list 页都会当场 CAPACITY——配置"自洽"
        // 却永远不可用（评审 r5 R5-W-3）。
        if self.max_ack_bytes > self.max_inflight_bytes_per_session {
            return Err(FileError::new(
                code::CONFIG,
                "max_ack_bytes must be <= max_inflight_bytes_per_session, else a full-size ack can never be charged",
            ));
        }
        // 单源失败额度必须落在"至少锁得住一个身份、又不至于比整张表还宽松"之间
        //（G15：这是**爆炸半径**上限，不是 QPS 上限）。低于 `lockout_after` 的话，
        // 任何身份都还没被锁、它的源就先被锁，等于把两层键塌成一层；高于
        // `max_throttle_buckets × lockout_after` 的话，表满 → 全局窗口这条大路
        // 永远先到，这条限额就是死配置。
        if self.max_failures_per_source < self.lockout_after {
            return Err(FileError::new(
                code::CONFIG,
                "max_failures_per_source must be >= lockout_after, else no identity can ever reach its own threshold",
            ));
        }
        if self.max_failures_per_source
            > self.max_throttle_buckets.saturating_mul(self.lockout_after)
        {
            return Err(FileError::new(
                code::CONFIG,
                "max_failures_per_source must be <= max_throttle_buckets * lockout_after, else the table-overflow gate always fires first and this one is dead config",
            ));
        }
        if self.max_browser_sessions > self.max_sessions {
            return Err(FileError::new(
                code::CONFIG,
                "max_browser_sessions must not exceed max_sessions",
            ));
        }
        // A page larger than the SCTP budget can never be flushed, and a page
        // larger than the per-session inflight budget defeats backpressure.
        if self.chunk_bytes > self.max_buffered_amount {
            return Err(FileError::new(
                code::CONFIG,
                "chunk_bytes must be <= max_buffered_amount, else a page can never be sent",
            ));
        }
        if self.chunk_bytes > self.max_inflight_bytes_per_session {
            return Err(FileError::new(
                code::CONFIG,
                "chunk_bytes must be <= max_inflight_bytes_per_session",
            ));
        }
        // The ack that reports a page must itself fit in the shared budget;
        // V1's oversized ack head-blocked the control channel forever.
        if self.max_ack_bytes > self.max_buffered_amount {
            return Err(FileError::new(
                code::CONFIG,
                "max_ack_bytes must be <= max_buffered_amount",
            ));
        }
        // 下限同样要交叉校验：ack 预算装不下"信封 + 一个条目"时，每个 list 页
        // 都会截断成 0 条目——客户端永远翻不完目录，而且看起来"没报错"。
        // （评审 WARN：旧 validate 只管上限，不管 entries × name 的字节数。）
        let min_ack = LIST_ACK_ENVELOPE_BYTES
            .checked_add(ENTRY_ACK_OVERHEAD_BYTES)
            .ok_or_else(|| FileError::new(code::OVERFLOW, "ack floor overflow"))?;
        if self.max_ack_bytes < min_ack {
            return Err(FileError::new(
                code::CONFIG,
                format!(
                    "max_ack_bytes must be >= {min_ack} (list envelope + one entry), \
                     else every list page truncates to zero entries"
                ),
            ));
        }
        // per-session in-flight 与共享发送预算由同一事件释放（`settle_file`），
        // 所以 in-flight 永远不可能超过预算：高于预算的上限是够不到的死配置。
        // 这条替代了旧的 `max_sessions * inflight <= buffered * 64`——那个 64
        // 是没有推导的魔数，实际允许 32-64 倍超配（评审 WARN）。总量本来就由
        // 共享预算封顶，不需要再乘一个会话数。
        if self.max_inflight_bytes_per_session > self.max_buffered_amount {
            return Err(FileError::new(
                code::CONFIG,
                "max_inflight_bytes_per_session must be <= max_buffered_amount, \
                 else the per-session ceiling can never be reached",
            ));
        }
        // Read handles must cover at least one handle per session, otherwise the
        // engine would have to evict handles it is still serving.
        if self.max_read_handles < self.max_sessions {
            return Err(FileError::new(
                code::CONFIG,
                "max_read_handles must be >= max_sessions",
            ));
        }
        Ok(())
    }
}

/// Which transport backs a root. This is not cosmetic: the non-overwriting
/// publish promised by G14 is implementable on the local engine (`hard_link`
/// fails on an existing destination) but **not** over SFTP with `ssh2` 0.9.6 —
/// libssh2 advertises and pins SFTP v3 (`include/libssh2_sftp.h:51`), and the
/// rename flags are only put on the wire when `sftp->version >= 5`
/// (`src/sftp.c:2833-2834`), so `Some(ATOMIC|NATIVE)` and `None` produce
/// byte-identical packets. The real primitive (`SSH_FXP_POSIX_RENAME`,
/// `libssh2_sftp_posix_rename_ex`) is not wrapped by the crate. Rather than ship
/// an upload path that silently overwrites, an SFTP-backed root refuses every
/// mutation (fail-closed, owner decision 2026-10-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Local,
    Sftp,
}

impl BackendKind {
    pub fn allows_mutation(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// A configured export directory. Construction is the only place where a root
/// becomes canonical, and a non-canonical configured root is rejected (G13).
#[derive(Debug, Clone)]
pub struct SandboxRoot {
    name: String,
    canonical: PathBuf,
    read_only: bool,
    backend: BackendKind,
}

impl SandboxRoot {
    /// Rejects: missing dir, non-canonical spelling (contains `..`, is a symlink,
    /// or is not byte-identical to its canonicalized form).
    pub fn open(name: impl Into<String>, configured: &Path, read_only: bool) -> FileResult<Self> {
        let name = name.into();
        let meta = std::fs::metadata(configured)
            .map_err(|e| FileError::new(code::CONFIG, format!("root {name}: {e}")))?;
        if !meta.is_dir() {
            return Err(FileError::new(
                code::CONFIG,
                format!("root {name} is not a directory"),
            ));
        }
        // Reject a root that is itself a symlink before canonicalization hides it.
        let link = std::fs::symlink_metadata(configured)
            .map_err(|e| FileError::new(code::CONFIG, format!("root {name}: {e}")))?;
        if link.file_type().is_symlink() {
            return Err(FileError::new(
                code::NON_CANONICAL_ROOT,
                format!("root {name} is a symlink; a sandbox root must be a real directory"),
            ));
        }
        let canonical = configured
            .canonicalize()
            .map_err(|e| FileError::new(code::CONFIG, format!("root {name}: {e}")))?;
        // 逐字节比较，不用 Path 的相等性：Path 比较会归一化掉 "." 与尾斜杠，
        // 用它比较 "/x/." 与 "/x" 会得到"相等"，这条守卫就形同不存在（实测踩过）。
        // Windows 的 canonicalize 会加 \\?\ 前缀，故先剥掉再比。
        let canonical_stripped = {
            let s = canonical.to_string_lossy();
            match s.strip_prefix(r"\\?\") {
                Some(rest) => PathBuf::from(rest.to_string()),
                None => canonical.clone(),
            }
        };
        let has_dot_component = configured
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir));
        if has_dot_component || canonical_stripped.as_os_str() != configured.as_os_str() {
            return Err(FileError::new(
                code::NON_CANONICAL_ROOT,
                format!(
                    "root {name} must be given in canonical form: {configured:?} vs {canonical:?}"
                ),
            ));
        }
        Ok(Self {
            name,
            canonical,
            read_only,
            backend: BackendKind::Local,
        })
    }

    /// SFTP 根：路径是**远端** POSIX 路径，不能拿本地 `canonicalize` 去规范化它
    /// （那会把它当本地路径解析）。这里只检查形状（绝对、无 `..`、非空），
    /// 并把后端标记成 `Sftp`：M1 没有实现 SFTP 传输，所以任何 IO 都会被
    /// `require_local_io` 拒；变更类操作则被 `require_writable` 永久拒（G14）。
    pub fn open_sftp(
        name: impl Into<String>,
        remote_path: &str,
        read_only: bool,
    ) -> FileResult<Self> {
        let name = name.into();
        let path = Path::new(remote_path);
        if !path.is_absolute() {
            return Err(FileError::new(
                code::CONFIG,
                format!("sftp root {name} must be an absolute remote path: {remote_path:?}"),
            ));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(FileError::new(
                code::NON_CANONICAL_ROOT,
                format!("sftp root {name} must not contain . or ..: {remote_path:?}"),
            ));
        }
        Ok(Self {
            name,
            canonical: path.to_path_buf(),
            read_only,
            backend: BackendKind::Sftp,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.canonical
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Componentwise resolution (G13). Every intermediate segment is checked
    /// with `symlink_metadata` (does *not* follow links), so a symlink anywhere
    /// on the path is refused rather than traversed. `.` is ignored; `..` and
    /// absolute components are refused; the final component may not be a symlink
    /// either (that is what makes list/read/write/remove all agree).
    pub fn resolve(&self, rel: &str) -> FileResult<PathBuf> {
        let mut current = self.canonical.clone();
        for comp in Path::new(rel).components() {
            match comp {
                Component::CurDir => continue,
                Component::Normal(seg) => {
                    current.push(seg);
                }
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(FileError::new(
                        code::OUTSIDE_ROOT,
                        format!(
                            "root {:?}: relative path may not contain .. or be absolute: {rel:?}",
                            self.name
                        ),
                    ));
                }
            }
            // Every segment, including the last one, must not be a symlink we traverse.
            let meta = match std::fs::symlink_metadata(&current) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Missing is fine for write/mkdir targets (they create it) and
                    // becomes NOT_FOUND for read/stat/remove, decided by the caller.
                    // Resolution MUST continue over the remaining components: stopping
                    // here would silently truncate `a/b/c` to `a` and publish bytes
                    // under the wrong prefix (N3-4/N3-9 fix the output path).
                    continue;
                }
                Err(e) => return Err(FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}"))),
            };
            if meta.file_type().is_symlink() {
                return Err(FileError::new(
                    code::SYMLINK_ESCAPE,
                    format!("path component is a symlink: {:?}", current),
                ));
            }
        }
        // Belt and braces: the resolved path must still sit under the root.
        Self::ensure_within(&self.canonical, &current, rel)?;
        Ok(current)
    }

    fn ensure_within(root: &Path, candidate: &Path, rel: &str) -> FileResult<()> {
        if candidate.starts_with(root) {
            Ok(())
        } else {
            Err(FileError::new(
                code::OUTSIDE_ROOT,
                format!("{rel:?} resolves outside the root: {:?}", candidate),
            ))
        }
    }

    /// Post-operation re-resolve (G21/G13): after bytes crossed the boundary we
    /// re-check that the path we actually touched is still inside the root and
    /// still not a symlink. Returns true when the check passed.
    pub fn reverify(&self, abs: &Path, rel: &str) -> FileResult<bool> {
        let meta = std::fs::symlink_metadata(abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(FileError::new(
                code::SYMLINK_ESCAPE,
                format!("became a symlink before the operation completed: {rel:?}"),
            ));
        }
        let canon = abs
            .canonicalize()
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        Self::ensure_within(&self.canonical, &canon, rel)?;
        Ok(true)
    }

    fn require_writable(&self) -> FileResult<()> {
        if !self.backend.allows_mutation() {
            // G14 fail-closed：没有可用的无覆盖改名原语，就不提供会造成静默覆盖的
            // 写路径。这不是"待办"，而是契约的一部分（owner 2026-10-11 选定）。
            return Err(FileError::new(
                code::UNSUPPORTED,
                format!(
                    "root {:?} is an {:?} backend: mutation requires a non-overwriting \
                     publish primitive that the current dependency cannot express",
                    self.name, self.backend
                ),
            ));
        }
        if self.read_only {
            return Err(FileError::new(code::READ_ONLY, self.name.clone()));
        }
        Ok(())
    }

    /// M1 只实现本地后端。任何落在本地文件系统上的动作，对 SFTP 根都必须显式拒绝，
    /// 而不是"看起来能跑"（远端路径在本地不存在时会得到误导性的 NOT_FOUND）。
    fn require_local_io(&self) -> FileResult<()> {
        if self.backend != BackendKind::Local {
            return Err(FileError::new(
                code::UNSUPPORTED,
                format!("root {:?} has no implemented transport yet", self.name),
            ));
        }
        Ok(())
    }

    pub fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Relative display path, computed from the canonical root.
    pub fn display_rel(&self, abs: &Path) -> String {
        abs.strip_prefix(&self.canonical)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| abs.to_string_lossy().replace('\\', "/"))
    }
}

/// A single directory entry in a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
}

/// One page of a listing (G17): `truncated` + `next_offset` are mandatory, and
/// a truncated page is never marked complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    pub entries: Vec<Entry>,
    pub next_offset: usize,
    pub truncated: bool,
    pub is_complete_list: bool,
}

/// One page of file bytes (G18, aligned with N3-9's page semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPage {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub next_offset: u64,
    pub eof: bool,
}

/// Accounting for open read handles (G16). One entry per (session, path), so N
/// chunks of one download cost **one** handle; V1 allocated one per chunk and
/// died around handle ~1022.
///
/// 计数单位是"不同的 (会话, 路径)"，不是引用计数：旧实现 `live() = values().sum()`
/// 与自己的文档矛盾（第二次 acquire 同一路径就报 2 个活句柄），预算因此比声明的
/// 更紧、且 `peak` 记的是分片数而不是并发文件数（评审 r2 W-9 顺带查出）。
#[derive(Debug)]
pub struct HandleRegistry {
    open: HashSet<(u64, String)>,
    budget: usize,
    pub peak: usize,
}

impl HandleRegistry {
    pub fn new(budget: usize) -> Self {
        Self {
            open: HashSet::new(),
            budget,
            peak: 0,
        }
    }

    /// Returns the number of live handles after acquiring. A repeated chunk of
    /// the same (session, path) costs nothing, which is the whole point of
    /// server-issued stream identity (G16).
    pub fn acquire(&mut self, session: u64, path: &str) -> FileResult<usize> {
        let key = (session, path.to_string());
        if self.open.contains(&key) {
            return Ok(self.live());
        }
        if self.live() >= self.budget {
            return Err(FileError::new(
                code::CAPACITY,
                format!(
                    "read handle budget exhausted ({} open, budget {})",
                    self.live(),
                    self.budget
                ),
            ));
        }
        self.open.insert(key);
        self.peak = self.peak.max(self.live());
        Ok(self.live())
    }

    pub fn release(&mut self, session: u64, path: &str) {
        self.open.remove(&(session, path.to_string()));
    }

    pub fn live(&self) -> usize {
        self.open.len()
    }
}

/// The engine's per-file byte accounting for one upload stream (G18).
#[derive(Debug)]
pub struct UploadStream {
    pub id: u64,
    pub session: u64,
    /// The root the stream was opened on. Commit must publish through *this*
    /// root: taking the caller's `root` argument at commit time would let a
    /// stream opened on a writable root land in a `read_only` one, or hand an
    /// SFTP root's remote path to the local resolver (评审 r2 NEW-1).
    pub root: String,
    pub rel: String,
    /// Contiguous bytes staged in the `.part` file; the only number ever acked.
    /// "Staged" is **not** a durability claim: `flush()` on `std::fs::File` is a
    /// no-op, so the bytes are only guaranteed on stable storage after
    /// `commit_upload` calls `sync_all()` before publishing (评审 WARN：
    /// 逐片 fsync 会把上传吞吐打到不可用， durability 声明因此后移到 commit)。
    pub staged: u64,
    pub declared_len: Option<u64>,
    pub hasher: Sha256,
    pub hashed_bytes: u64,
    /// Bytes re-read from disk for duplicate-page verification, charged against
    /// `max_rehash_bytes_per_stream` (the DoS that budget actually covers).
    pub rehash_bytes: u64,
    pub part_path: PathBuf,
    pub file: std::fs::File,
    pub last_activity: Instant,
}

/// A file session: identity, budget, streams, activity (G15/G16/G21).
#[derive(Debug)]
pub struct FileSession {
    pub id: u64,
    pub principal: String,
    /// Where the peer came from, recorded at authentication. Used for the
    /// per-peer session quota (G16) and for clearing the right throttle bucket
    /// on teardown (评审 r2 N-8: a caller-supplied source could wipe someone
    /// else's lockout).
    pub source: String,
    pub inflight_bytes: usize,
    pub streams: BTreeMap<u64, UploadStream>,
    /// The field the idle sweeper reads. Every activity updates *this* field —
    /// V1 refreshed a different one, which made the timeout unreachable.
    pub last_activity: Instant,
    pub recycled: bool,
}

/// One throttle bucket: failures counted inside the **current** window, and when
/// the last one arrived. `last` is what makes the bucket decay — a count that
/// never goes stale is a count an attacker can keep warm forever, which is the
/// thing 评审 r4 R4-W-6 asked to settle. Owner decision for this batch: implement
/// the decay rather than write "legitimate users may be refused indefinitely" into
/// the product as an accepted cost.
#[derive(Debug, Clone, Copy)]
struct BucketState {
    count: usize,
    last: Instant,
}

/// Bucket key: a fixed-size digest of the identity, see [`Throttle::identity_key`].
type IdentityKey = [u8; 32];

/// One transport address's failure ledger inside the current window.
///
/// 为什么需要它：节流键是 (主体,源) 的**对**，所以一个源地址可以为任意多个自己
/// 不拥有的主体开桶，把 `max_throttle_buckets` 行额度池全部花掉（评审 r7 整改清单
/// 第 3 条、r8 R7-N-9）。这条限额管的是**爆炸半径**：一个 peer 在一个窗口里最多
/// 能贡献多少条失败，超过就锁这个源本身一个窗口。
#[derive(Debug, Clone, Copy)]
struct SourceLedger {
    count: usize,
    last: Instant,
}

/// `from` is at least one window in the past, so a failure that old starts a
/// **new** window instead of advancing the old count. A free function rather than
/// a method because `HashMap::retain` holds the map mutably and a `&self` helper
/// would collide with it.
fn stale(window: Duration, from: Instant, now: Instant) -> bool {
    now.saturating_duration_since(from) >= window
}

/// Bounded authentication throttle (G15).
#[derive(Debug, Default)]
pub struct Throttle {
    buckets: HashMap<IdentityKey, BucketState>,
    /// Overflow sink: while the table is full, failures of *new* identities land
    /// here instead of growing memory with forged volume (so
    /// `throttle_entries_bounded` is real). It decays on its own clock
    /// (`global_last`), so the fail-closed window must be **kept alive by
    /// continuing to inject fresh identities** — stop for one window and both the
    /// counter and the armed window are gone.
    global: usize,
    global_last: Option<Instant>,
    /// Fail-closed window for the overflowing population. The 旧行为 was
    /// fail-**open**: overflow failures only moved a private counter, `locked`
    /// was never written, and `authenticate` still compared the token, so
    /// rotating principals bought an unlimited number of guesses (评审 r2 NEW-3).
    global_locked_until: Option<Instant>,
    locked: HashMap<IdentityKey, Instant>,
    /// Per-transport-address failure ledger (blast-radius limit, see [`SourceLedger`]).
    source_failures: HashMap<[u8; 32], SourceLedger>,
    /// Live locks on those addresses. A locked source cannot authenticate at all
    /// during its window, so `succeed` can never be used to escape one.
    ///
    /// 这张表**也有**门禁（`arm_source`，r9 R9-W-2）：满了就升级为全局窗口，否则
    /// "账本满 ⇒ 陌生地址第一条就锁"那条分支会变成每次请求换一条表项的内存放大。
    source_locks: HashMap<[u8; 32], Instant>,
    max_buckets: usize,
    max_source_failures: usize,
    lockout: Duration,
    lockout_after: usize,
}

impl Throttle {
    pub fn new(
        max_buckets: usize,
        lockout_after: usize,
        lockout: Duration,
        max_source_failures: usize,
    ) -> Self {
        Self {
            buckets: HashMap::new(),
            global: 0,
            global_last: None,
            global_locked_until: None,
            locked: HashMap::new(),
            source_failures: HashMap::new(),
            source_locks: HashMap::new(),
            max_buckets,
            max_source_failures,
            lockout,
            lockout_after,
        }
    }

    /// 时钟加法必须 `checked_add`（评审 r5 R5-W-2：G20 要求 panic-free-by-construction，
    /// 而 `Instant + Duration` 在 std 语义下会 panic）。`validate()` 已把窗口封在 24h
    /// 内，所以正常路径不会溢出；万一溢出（时钟已到平台边界），返回 `None` 表示
    /// "这次不写入持久锁，但本次仍按锁定处理"——绝不退成"立即过期后照常比令牌"，
    /// 那等于把 fail-closed 换成 fail-open（评审 r6 NOTE-2）。
    fn lock_until(&self, now: Instant) -> Option<Instant> {
        now.checked_add(self.lockout)
            .or_else(|| now.checked_add(Duration::from_secs(3600)))
    }

    /// The bucket key is a SHA-256 **digest** of the identity, not a truncated
    /// copy of it. Two independent reasons, both raised in review:
    /// - memory: a digest is 32 bytes, so `max_throttle_buckets` bounds *bytes*
    ///   and not merely the number of rows. The previous scheme clipped both halves
    ///   to a fixed label length (128 B, 评审 r5 R5-W-4 的处置), which bounded the
    ///   *labels* while still allocating a `String` per half per bucket;
    /// - attribution: a truncated key lets an attacker **aim** his failures at a
    ///   victim. "Same first 128 bytes, same total length" put him in the victim's
    ///   bucket, so `lockout_after` requests were enough to lock out one named
    ///   legitimate principal（评审 r6 NOTE-4）。Sharing a digest bucket now requires
    ///   a SHA-256 collision, which is not a "prefix + length" trick.
    ///
    /// Both halves are **length-prefixed** before hashing. Without that,
    /// `("ab", "c")` and `("a", "bc")` hash the same concatenation — a collision
    /// an attacker gets for free because he supplies both fields. Pinned by
    /// `throttle_identity_keys_do_not_collide_on_prefix_or_concatenation`.
    fn identity_key(principal: &str, source: &str) -> IdentityKey {
        let mut h = Sha256::new();
        h.update((principal.len() as u64).to_le_bytes());
        h.update(principal.as_bytes());
        h.update((source.len() as u64).to_le_bytes());
        h.update(source.as_bytes());
        h.finalize().into()
    }

    /// Address-only digest for the per-source ledger. Deliberately a **different**
    /// key space from [`Throttle::identity_key`] (which mixes both halves), so a
    /// source ledger can never alias a pair bucket.
    fn source_key(source: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"nexus-source");
        h.update((source.len() as u64).to_le_bytes());
        h.update(source.as_bytes());
        h.finalize().into()
    }

    /// Expire locks and the global window, and drop idle buckets.
    ///
    /// All three decays are the same statement: a failure only counts against the
    /// identity (or the overflowing population) that is *still* failing. Expired
    /// `locked` entries are dropped so dead locks cannot occupy table rows, and
    /// buckets whose last failure is a window old are dropped so (a) forged volume
    /// cannot permanently squat the table — an honest newcomer gets its own bucket
    /// again within one window — and (b) the overflow counter cannot be kept warm
    /// by a trickle（评审 r3 R3-W-2 只要求全局窗口归零；R4-W-6 把同一条性质推到
    /// 桶上，owner 决定实现衰减而不是登记为可接受代价）。
    ///
    /// 这里是**唯一**的衰减点：`record_failure` 先调它再计数，所以任何活到计数
    /// 那一步的行都已经落在窗口内，不需要也不可能再判一次。
    fn decay(&mut self, now: Instant) {
        let window = self.lockout;
        self.locked.retain(|_, until| *until > now);
        self.buckets
            .retain(|_, state| !stale(window, state.last, now));
        self.source_failures
            .retain(|_, ledger| !stale(window, ledger.last, now));
        self.source_locks.retain(|_, until| *until > now);
        if let Some(until) = self.global_locked_until {
            if until <= now {
                self.global_locked_until = None;
            }
        }
        if self
            .global_last
            .is_some_and(|last| stale(window, last, now))
        {
            self.global_last = None;
            self.global = 0;
        }
    }

    pub fn is_locked(&self, principal: &str, source: &str) -> bool {
        let now = Instant::now();
        let key = Self::identity_key(principal, source);
        // 读侧不跑 `decay`（它是 `&self`），所以可能看到过期项——方向是安全的：
        // 过期锁在这里也判 false，而写侧的下一次 `record_failure` 会把它们清掉，
        // 内存上界由写侧保证。
        if let Some(until) = self.locked.get(&key) {
            if *until > now {
                return true;
            }
        }
        // 全局窗口对**所有**主体生效。旧写法额外要求"该主体不在 buckets 里"，
        // 于是把表填满的那批 principal 恰好被豁免，成为永久绕开锁定点
        // （评审 r3 R3-NEW-2：换了人群的同一条 NEW-3）。
        if matches!(self.global_locked_until, Some(until) if until > now) {
            return true;
        }
        // 单源限额武装的地址锁：锁的是**这个传输地址**，不牵连别的源，也不升级为
        // 全体拒服务（G15 代价 (3) 的爆炸半径那一道）。同样在令牌比较之前短路。
        let skey = Self::source_key(source);
        matches!(self.source_locks.get(&skey), Some(until) if *until > now)
    }

    /// Record a failure; returns true if this pushed the identity — or the
    /// overflowing population — into a lockout window.
    pub fn record_failure(&mut self, principal: &str, source: &str) -> bool {
        let now = Instant::now();
        self.decay(now);
        let key = Self::identity_key(principal, source);
        // 单源额度先记账：两层键的哪一条分支都不能豁免它（一个地址把失败摊到
        // 很多主体上，正是这道限额要抓的形状）。
        let source_armed = self.charge_source(source, now);
        if self.buckets.len() >= self.max_buckets && !self.buckets.contains_key(&key) {
            // `decay()` above already zeroed `global` when `global_last` is a full
            // window old, which is exactly why a flood must be **sustained** to
            // keep the fail-closed window armed.
            self.global = self.global.saturating_add(1);
            self.global_last = Some(now);
            if self.global >= self.lockout_after {
                if let Some(until) = self.lock_until(now) {
                    self.global_locked_until = Some(until);
                }
                return true;
            }
            return source_armed;
        }
        // `decay` 已经用**同一个** `now`、同一个窗口谓词丢掉了过期行，所以活下来的
        // 行按定义就在当前窗口内：在这里再判一次 `stale` 是结构上不可达的冗余分支
        // （第八片实测：把那条守卫改成恒真，当时 61 条单测照样全绿 ⇒ 它零杀伤力）。衰减只有
        // `decay` 一个机制，单点可杀（变异 M1）。
        let count = match self.buckets.get(&key).copied() {
            Some(previous) => previous.count.saturating_add(1),
            None => 1,
        };
        self.buckets.insert(key, BucketState { count, last: now });
        if count >= self.lockout_after {
            // 每次达到阈值都重新上锁（锁可续期）。时钟边界（`None`）时不写持久锁，
            // 但这次调用仍按"已锁定"回给 authenticate。
            //
            // `locked` 满了才升级为全局窗口这一支是**纵深防御，不是产品路径**。
            // 三个前提缺一不可，写全在这里（r8 R8-W-3 指出我上一版漏了第一句，
            // 于是"不可达"从证明退化成断言）：
            // (a) 行与锁的死亡条件**逐字等价**：锁判 `until > now`（`until = arm + w`），
            //     行判 `now - last >= w` 即作废，且武装那次两者写的是同一个 `now`；
            //     锁定期内 `authenticate` 先短路、既不刷新行也不刷新锁。
            // (b) 行只有两个消失途径：`decay`（按 (a) 与锁同时死）与 `succeed`
            //     （它只在 `is_locked == false` 时才可达 ⇒ 有活锁的行不会被它删）。
            //     会话拆除**不再**是第三个途径（r8 R8-W-2 之后 `close_session`
            //     什么都不清，理由见 `Throttle::succeed` 的历史三段）。
            // (c) 新行只在本函数开头那道 `buckets.len() >= max_buckets` 不成立时才产生。
            // 由 (a)(b)：每条活锁都对应一行活行 ⇒ `locked.len() ≤ buckets.len()`；
            // 由 (c)：`buckets.len() ≤ max_buckets`。所以 `locked.len() == max_buckets`
            // 要求**所有在册行都带活锁**，而那时任何新身份都先撞 (c) 走溢出分支，
            // 走不到这里 ⇒ 经 `authenticate` 不可达。r7 §3.2 证的是同一件事，我当时
            // 把它抄过来当前提用，没有复核它对"forget 会删行"这一旧行为的依赖——
            // 第八片删行不删锁的写法会把这条不变式弄假，第九片把删行整个去掉之后它才
            // 重新成立，且现在有了新的观测面：`Throttle::locks()`/`FileEngine::throttle_locks()`
            // （锁表大小此前全仓不可读，"表项有界"对锁表那一半是零可红对象，r8 R8-W-3）。
            // 实测（复验于干净树 ada41e4，69 单测 / 24 条本场景期望；这一行之后的改动
            // 只有散文，数字与判据不变，bindings 全量见案卷《M1 第十一片》）：把这支整个关掉 ⇒ 69 全绿、24 条冻结期望字段
            // 无一翻转（这与上面的不可达性一致，不是"测试没覆盖到"）；把 `decay` 的
            // 过期锁回收改成恒真 ⇒ 只有
            // `expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window` 红，
            // 也就是说它唯一的正向覆盖就是"回收坏了"那一类，正是这支要兜的缺陷。
            // G15 里 fail-closed 的**实际**机制只有溢出计数那一条，措辞与此一致。
            if let Some(until) = self.lock_until(now) {
                if self.locked.len() >= self.max_buckets {
                    self.global_locked_until = Some(until);
                } else {
                    self.locked.insert(key, until);
                }
            }
            return true;
        }
        // 这一条失败没把这个**身份**推到阈值，但可能刚好花完它所在地址的额度 ⇒
        // 调用者要拿到"被锁了"的真值，否则 authenticate 会把一次已经武装源锁的尝试
        // 当成普通拒绝继续发令牌比较。
        source_armed
    }

    /// Charge one failure to its transport address.
    ///
    /// 返回 `true` 表示这次记账**武装了源锁**（`authenticate` 据此回 THROTTLED）。
    /// 额度位本身与两层键同一条原则：账本满时不给陌生地址建行而是**当场锁它**
    /// （fail-closed），而 `arm_source` 对锁表做同样的事——满了就升级为全局窗口。
    /// 所以节流结构的内存上界是**四张表各自 ≤ `max_throttle_buckets` + 定长键 +
    /// `BucketState`**，不是"见过多少个源"（r9 R9-W-2 之前这句是假的：源锁表没门禁）。
    fn charge_source(&mut self, source: &str, now: Instant) -> bool {
        let skey = Self::source_key(source);
        let count = match self.source_failures.get(&skey).copied() {
            Some(previous) => previous.count.saturating_add(1),
            None if self.source_failures.len() >= self.max_buckets => {
                // 账本满：陌生地址的第一条失败就锁它（fail-closed），不给它建行。
                return self.arm_source(skey, now);
            }
            None => 1,
        };
        self.source_failures
            .insert(skey, SourceLedger { count, last: now });
        if count >= self.max_source_failures {
            // 额度花完：先算锁、再删账本行（r9 R9-N-3：删行在前会让我们在
            // "时钟边界拿不到 `until`"那条分支里把该地址的账清掉却不落地，
            // 等于白送一次额度重置）。
            let armed = self.arm_source(skey, now);
            self.source_failures.remove(&skey);
            return armed;
        }
        false
    }

    /// Lock one transport address for a window, with the **same** two guarantees
    /// the pair table gives: the table cannot grow without bound, and a clock
    /// edge that yields no `until` still reports "armed" rather than falling back
    /// to "go ahead and compare tokens" (`lock_until`'s own promise).
    ///
    /// 源锁表必须自己也有门禁，这点是 r9 R9-W-2 抓到的：上面"账本满 ⇒ 陌生地址
    /// 第一条失败就锁"这条分支，若锁表无界，就成了**每 1 次请求换 1 条表项**的
    /// 内存放大路径——恰恰是最便宜的那种注入。表满时与两层键同一条大路：升级为
    /// 全局窗口（代价是那一窗口对所有人 fail-closed，与 `locked` 满时同形）。
    fn arm_source(&mut self, skey: [u8; 32], now: Instant) -> bool {
        let Some(until) = self.lock_until(now) else {
            return true;
        };
        if self.source_locks.len() >= self.max_buckets {
            self.global_locked_until = Some(until);
            return true;
        }
        self.source_locks.insert(skey, until);
        true
    }

    /// Live rows in the table. 观测口径按窗口过滤（读侧不跑 `decay`，它是 `&self`），
    /// 所以这里报的是"还作数的失败"而不是底层 `HashMap` 的物理行数。
    ///
    /// 两个上界来源要分开，别混成一句（r7 R7-W-1/§3.2 的口径）：
    /// (1) **物理行数有界**来自 `record_failure` 的准入行门禁（新行只在
    /// `len < max_buckets` 时才产生），与回收无关；
    /// (2) `decay` 的回收决定的是行**会不会死**（洪水占位能否自愈），不是行数上限。
    ///
    /// 探针与单测判的是存活值语义；`throttle_entries_bounded` 那条期望因此在慢 CI 上
    /// 测不到"死行占位"这一类问题——那一类由
    /// `expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window` 钉。
    pub fn buckets(&self) -> usize {
        let (window, now) = (self.lockout, Instant::now());
        self.buckets
            .values()
            .filter(|state| !stale(window, state.last, now))
            .count()
    }

    /// Failures still counted in live buckets (observability for **bucket
    /// decay**): a quiet identity's count must drop back to zero by itself, which
    /// is what stops forged volume from permanently squatting the table.
    pub fn failure_count(&self) -> usize {
        let (window, now) = (self.lockout, Instant::now());
        self.buckets
            .values()
            .filter(|state| !stale(window, state.last, now))
            .map(|state| state.count)
            .sum()
    }

    /// Live overflow failures (same read-side window filter as `buckets`).
    pub fn global(&self) -> usize {
        let (window, now) = (self.lockout, Instant::now());
        match self.global_last {
            Some(last) if stale(window, last, now) => 0,
            _ => self.global,
        }
    }

    pub fn globally_locked(&self) -> bool {
        self.global_locked_until
            .is_some_and(|until| until > Instant::now())
    }

    /// Live rows in `locked` (read side: expired entries count as zero).
    ///
    /// 这条访问器存在的理由（评审 r8 R8-W-3）：G15 标题那句"计数与表项**有界**"此前
    /// 只对 `buckets` 有可红对象，锁表大小全仓不可观测，于是"锁表会不会长大"这个问题
    /// 在测试面上是空的。它和 `throttle_buckets()` 一起给出不变式
    /// `locked.len() ≤ buckets.len() ≤ max_throttle_buckets` 的唯一观测面。
    pub fn locks(&self) -> usize {
        let now = Instant::now();
        self.locked.values().filter(|until| **until > now).count()
    }

    /// Live per-source locks (blast-radius gate, G15 代价 (3) 的配套限额).
    pub fn source_locks_live(&self) -> usize {
        let now = Instant::now();
        self.source_locks
            .values()
            .filter(|until| **until > now)
            .count()
    }

    /// Live per-source ledgers, i.e. how many addresses are currently spending
    /// their allowance inside this window.
    pub fn source_ledgers(&self) -> usize {
        let (window, now) = (self.lockout, Instant::now());
        self.source_failures
            .values()
            .filter(|ledger| !stale(window, ledger.last, now))
            .count()
    }

    /// The **only** explicit clearing path: a successful authentication drops this
    /// identity's failure count (an armed lock can never reach this line, because
    /// `authenticate` short-circuits on `is_locked` first — that is what keeps
    /// `locked.len() ≤ buckets.len()` worth proving rather than assuming).
    ///
    /// 历史三段都留在这里，因为每一段都是上一段的前提被证伪之后的修正（会话拆除为什么
    /// 什么也不清，见 `FileEngine::close_session`）：
    /// 1. 最初有个 `forget()`，在会话拆除时同时删失败计数与已武装的锁。r7 实测把它的
    ///    两行删空**谁都不红**，而它的注释写着"asserted by the probe"——那条
    ///    `state_cleared_after_close` 跑在成功认证之后，成功早已由这里清过桶，
    ///    探针根本观测不到那个函数。
    /// 2. 第八片把行为翻成"只清计数、锁必须服完"，理由是会话号顺序自增、而当时
    ///    `close_session` 根本不校验调用方是不是会话所有者，"拆会话即解锁"等于
    ///    无限猜测预算。
    /// 3. r8 指出翻得不够：锁是由**计数**达到阈值才武装的，而清计数走的还是同一扇
    ///    当时没有归属检查的门 ⇒ 攻击者每 `lockout_after - 1` 次猜密替被冒用的身份
    ///    关一次会话，就把计数按定义钉在阈值之下，锁**永远不武装**——比解锁更省事。
    ///
    /// 于是这条路径整个被删掉（函数不存在了）：节流状态只由"这里的 `succeed`"与
    /// "窗口衰减 `decay`"两途清理。`succeed` 已经覆盖了那个被删函数唯一的正当收益
    /// （回来的合法主体不该背着旧账），删掉它不损失任何正向语义，反而把
    /// "锁不会比行多"的前提补回来：行只能因衰减或因成功而消失，而成功在有活锁时
    /// 根本走不到这里 ⇒ 孤锁没有来源。
    ///
    /// 同批把**归属检查**补上（`close_session(session, source)` 必须出示与会话相同的
    /// 传输地址），所以"替别人关会话"这一支从入口上就断了——**只这一支**：同一个
    /// crate 里 `abort_upload` 等按 id 删除暂存字节的动词仍不做归属证明，同类破坏面
    /// 原样保留（G16 明写这条边界，别把它读成"所有自增号入口都关上了"）。仍登记的
    /// 残余还有：地址是传输地址而不是凭证，同一 NAT 下能看见彼此地址的调用方互相
    /// 可判，凭证化要等 M2 给每条会话发 capability。两侧都有断言：
    /// `session_teardown_touches_no_throttle_state`、
    /// `idle_recycle_clears_no_throttle_state`；入口本身由
    /// `closing_another_peers_session_is_refused_and_leaves_it_intact` 与冻结期望
    /// `foreign_close_refused_and_session_survives` 钉住。
    pub fn succeed(&mut self, principal: &str, source: &str) {
        let key = Self::identity_key(principal, source);
        self.buckets.remove(&key);
    }
}

/// Shared SCTP send budget with class priority (G16). Terminal bytes are never
/// dropped; file-class messages are refused explicitly and counted.
///
/// 队列里存的是 **(会话号, 每条消息字节数)**，不是"一次事件"，也不是无归属的字节数：
/// - 按条计数（评审 r1 F2）：`usize::from(freed > 0)` 把挤掉 4 条记成 1 条；
/// - 按会话归属释放（评审 r2 NEW-2）：被挤掉的消息必须回冲**它自己会话**的 in-flight
///   额度，否则那个会话只能去 ack 一份它从未收到的页，此后永久 `CAPACITY`。
///
/// 消息按 FIFO 整条出队：SCTP 消息不可部分发送，所以 settle/drain 都只处理
/// 完整消息，宁可少释放也不虚报已发送。
#[derive(Debug)]
pub struct SendBudget {
    pub limit: usize,
    /// Terminal-class bytes currently waiting in the transport buffer.
    pub terminal_buffered: usize,
    /// File-class messages waiting to be flushed, oldest first: `(session, bytes)`.
    pub file_queue: VecDeque<(u64, usize)>,
    /// File-class messages squeezed out or refused, counted per message.
    pub file_drops: usize,
    /// Terminal-class sends the budget **accepted**. Naming matters: this is not
    /// a delivery confirmation (the transport hasn't been involved yet), so the
    /// old name `terminal_delivered` overstated it（评审 r3 N-8）.
    pub terminal_accepted: usize,
    pub terminal_drops: usize,
}

impl SendBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            terminal_buffered: 0,
            file_queue: VecDeque::new(),
            file_drops: 0,
            terminal_accepted: 0,
            terminal_drops: 0,
        }
    }

    pub fn file_buffered(&self) -> usize {
        self.file_queue.iter().map(|(_, b)| b).sum()
    }

    /// Bytes still holding budget on behalf of one session.
    pub fn file_buffered_for(&self, session: u64) -> usize {
        self.file_queue
            .iter()
            .filter(|(s, _)| *s == session)
            .map(|(_, b)| b)
            .sum()
    }

    pub fn buffered(&self) -> usize {
        self.terminal_buffered + self.file_buffered()
    }

    pub fn pending_file_messages(&self) -> usize {
        self.file_queue.len()
    }

    /// `buffered + bytes > limit`，但**不允许溢出**（评审 r5 R5-W-5：G20 要求
    /// panic-free-by-construction，而 `send_file_message` 的 `bytes` 是调用方给的）。
    /// 溢出按"放不下"处理，即 fail-closed。
    fn exceeds_limit(&self, bytes: usize) -> bool {
        match self.buffered().checked_add(bytes) {
            Some(total) => total > self.limit,
            None => true,
        }
    }

    /// Terminal has priority. **Always** hands back the file-class messages it
    /// evicted, including on the failure path — an eviction that is not returned
    /// is a session that keeps charging in-flight bytes for pages that are gone
    /// (评审 r3 R3-NEW-1：`Ok/Err` 二选一携带清单会把清单丢掉）。
    /// 返回 `(evicted, result)`，调用方必须先按清单回冲额度，再看 result。
    pub fn push_terminal(&mut self, bytes: usize) -> (Vec<(u64, usize)>, FileResult<()>) {
        let mut evicted: Vec<(u64, usize)> = Vec::new();
        if bytes > self.limit {
            // 一条比整个预算还大的终端消息永远发不出去；这种情况**一条文件消息都不该挤**，
            // 否则挤掉的字节白赔进去。
            self.terminal_drops += 1;
            return (
                evicted,
                Err(FileError::new(
                    code::CAPACITY,
                    format!(
                        "terminal message of {bytes} bytes exceeds the whole send budget {}",
                        self.limit
                    ),
                )),
            );
        }
        if self.exceeds_limit(bytes) {
            self.drain_file_reserve(bytes, &mut evicted);
            self.file_drops += evicted.len();
        }
        if self.exceeds_limit(bytes) {
            // Still no room (terminal-class bytes already occupy the buffer and
            // by definition those are never evicted): a hard capacity failure,
            // never a silent drop. The eviction above really happened, so the
            // list goes back to the caller even though this send failed.
            self.terminal_drops += 1;
            return (
                evicted,
                Err(FileError::new(code::CAPACITY, "terminal budget exhausted")),
            );
        }
        self.terminal_buffered += bytes;
        self.terminal_accepted += 1;
        (evicted, Ok(()))
    }

    pub fn push_file(&mut self, session: u64, bytes: usize) -> FileResult<()> {
        if bytes == 0 {
            return Ok(());
        }
        if self.exceeds_limit(bytes) {
            self.file_drops += 1;
            return Err(FileError::new(
                code::QUEUE_FULL,
                "shared send budget full; file class refused",
            ));
        }
        self.file_queue.push_back((session, bytes));
        Ok(())
    }

    /// Undo a `push_file` that a later gate rejected: the message never went out,
    /// so it must not hold budget. Only the just-pushed message is removed.
    pub fn unpush_file(&mut self, session: u64, bytes: usize) {
        if self.file_queue.back() == Some(&(session, bytes)) {
            self.file_queue.pop_back();
        }
    }

    /// Squeeze out the oldest file-class messages until `bytes` of terminal
    /// traffic fits, collecting every message actually evicted (counted per
    /// message by the caller, never as a single "eviction happened" event).
    fn drain_file_reserve(&mut self, bytes: usize, out: &mut Vec<(u64, usize)>) {
        // `buffered() <= limit` 是结构不变量，但按 G20 不靠注释保证：减法也走
        // saturating（评审 r6 NOTE-5）。
        let mut need = bytes.saturating_sub(self.limit.saturating_sub(self.buffered()));
        while need > 0 {
            match self.file_queue.pop_front() {
                Some(msg) => {
                    need = need.saturating_sub(msg.1);
                    out.push(msg);
                }
                None => break,
            }
        }
    }

    /// The transport flushed whole file-class messages of `session` totalling up
    /// to `bytes`. Returns the bytes actually freed — never a partial message.
    pub fn settle_file(&mut self, session: u64, bytes: usize) -> usize {
        // 严格只看队头：越过队头去释放后面的消息，等于给**还在传输缓冲里**的字节
        // 提前退额度（评审 r3 R3-W-4，复算件 [(s,12),(s,10)] 上 settle(s,10)
        // 旧实现会退 10）。跨会话的消息同样只能等它前面的先落地。
        let mut remaining = bytes;
        let mut freed = 0usize;
        while let Some(&(s, b)) = self.file_queue.front() {
            if s != session || b > remaining {
                break;
            }
            self.file_queue.pop_front();
            remaining -= b;
            freed += b;
        }
        freed
    }

    /// A session went away (closed or idle-recycled): every message still holding
    /// budget for it is released. Without this one churned peer pins the node-wide
    /// budget permanently (评审 r2 NEW-2 第 2 点).
    pub fn release_session(&mut self, session: u64) -> usize {
        let before = self.file_buffered();
        self.file_queue.retain(|(s, _)| *s != session);
        before - self.file_buffered()
    }

    /// The transport flushed `bytes` of terminal-class traffic.
    pub fn settle_terminal(&mut self, bytes: usize) {
        self.terminal_buffered = self.terminal_buffered.saturating_sub(bytes);
    }
}

/// 调用方可控字符串的记账长度上限（评审 r5 R5-W-4）。"审计环有界"只有在值也有界时
/// 才是事实：认证主体名、源地址、审计里的 principal/root/rel 都来自外部输入
/// （其中 principal 在令牌校验**之前**就被写下），不裁长度就是
/// "行数 × 任意长字符串"。裁剪只损失归因精度，不改变任何判定方向，且带可见标记。
///
/// 节流表的键**不走**这条路径：它存的是身份的 32 字节摘要（`Throttle::identity_key`），
/// 既不需要裁长度，也不再付 `String` 分配（评审 r6 NOTE-4 的裁决：摘要键让
/// "前缀 + 总长可控"的身份碰撞变成"需要 SHA-256 碰撞"）。
const AUDIT_FIELD_MAX_BYTES: usize = 256;

/// Byte-bounded copy of a caller-supplied label, cutting on a char boundary and
/// appending how much was dropped (so the truncation is visible in the record).
fn bounded_label(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[+{}B]", &s[..end], s.len() - end)
}

/// Audit ring capacity. Bounded on purpose: an unbounded log is a memory-exhaustion
/// path driven by the very refusals it records. Overflow drops the oldest line and
/// bumps `FileEngine::audit_dropped`, so the rotation is observable.
const AUDIT_CAPACITY: usize = 8192;

/// Serialized-cost model for one list ack, measured from the JSON shape the probe
/// emits (`{"next_offset":0,"entries":[...],"truncated":false,"is_complete_list":true}`
/// = 72 bytes empty; one entry `{"name":"x","is_dir":false,"is_symlink":false,"size":1}`
/// = 52 bytes plus the name). M2 owns the real wire encoding and must re-measure
/// these two numbers there; until then they are the ceiling `list` enforces, and
/// `validate()` refuses an ack budget that could not carry even one entry.
const LIST_ACK_ENVELOPE_BYTES: usize = 72;
const ENTRY_ACK_OVERHEAD_BYTES: usize = 52;

/// One audit line (G21): refusals are recorded too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub session: u64,
    pub principal: String,
    pub root: String,
    pub action: &'static str,
    pub rel: String,
    pub result_code: String,
}

/// The engine. `Default::default()` limits are validated at construction.
pub struct FileEngine {
    limits: FileLimits,
    roots: HashMap<String, SandboxRoot>,
    sessions: HashMap<u64, FileSession>,
    next_session: u64,
    next_stream: u64,
    handles: HandleRegistry,
    throttle: Throttle,
    audit: VecDeque<AuditRecord>,
    audit_dropped: usize,
    /// Incremented **only** where `constant_time_eq` runs (see
    /// `FileEngine::token_comparisons`).
    token_compares: usize,
    token: String,
    /// G16 共享发送预算。引擎**自己持有**它，页/ack 出门前必须先过账；
    /// 之前预算只在探针里手搓一份，`quota-backpressure` 案证明的是模型
    /// 而不是产品路径（评审 F1）。
    budget: SendBudget,
}

impl FileEngine {
    pub fn new(
        limits: FileLimits,
        roots: Vec<SandboxRoot>,
        token: impl Into<String>,
    ) -> FileResult<Self> {
        limits.validate()?;
        // Capture before `limits` moves into the engine below.
        let read_handles = limits.max_read_handles;
        let buffered = limits.max_buffered_amount;
        let mut map = HashMap::new();
        for r in roots {
            if map.contains_key(r.name()) {
                return Err(FileError::new(
                    code::CONFIG,
                    format!("duplicate root {:?}", r.name()),
                ));
            }
            map.insert(r.name().to_string(), r);
        }
        if map.is_empty() {
            return Err(FileError::new(
                code::CONFIG,
                "at least one root must be configured",
            ));
        }
        let token = token.into();
        if token.is_empty() {
            return Err(FileError::new(code::CONFIG, "auth token must not be empty"));
        }
        let throttle = Throttle::new(
            limits.max_throttle_buckets,
            limits.lockout_after,
            limits.lockout_window,
            limits.max_failures_per_source,
        );
        Ok(Self {
            limits,
            roots: map,
            sessions: HashMap::new(),
            next_session: 1,
            next_stream: 1,
            handles: HandleRegistry::new(read_handles),
            throttle,
            audit: VecDeque::new(),
            audit_dropped: 0,
            token_compares: 0,
            token,
            budget: SendBudget::new(buffered),
        })
    }

    pub fn limits(&self) -> &FileLimits {
        &self.limits
    }

    pub fn audit(&self) -> &VecDeque<AuditRecord> {
        &self.audit
    }

    /// Audit lines dropped because the bounded buffer was full. Non-zero means
    /// the log rotated, not that nothing happened.
    pub fn audit_dropped(&self) -> usize {
        self.audit_dropped
    }

    pub fn handle_stats(&self) -> (usize, usize) {
        (self.handles.live(), self.handles.peak)
    }

    pub fn throttle_buckets(&self) -> usize {
        self.throttle.buckets()
    }

    /// Overflow failures the bounded table could not hold (G15 observability).
    pub fn throttle_overflow(&self) -> usize {
        self.throttle.global()
    }

    /// Failures still counted in live buckets (G15 observability for **bucket
    /// decay**): a quiet identity's count must drop back to zero by itself, which
    /// is what stops forged volume from permanently squatting the table.
    pub fn throttle_failures(&self) -> usize {
        self.throttle.failure_count()
    }

    /// True while the fail-closed global lockout window is active.
    pub fn throttle_globally_locked(&self) -> bool {
        self.throttle.globally_locked()
    }

    /// Is **this** (主体,源) pair inside an individual lockout right now? The
    /// table itself only stores digests, so attribution goes through the audit
    /// ring; this accessor exists so the contract probe can assert per-pair
    /// separation (评审 r7 R7-N-6: the length-prefix property had a single unit
    /// assertion and zero frozen expectations).
    pub fn throttle_locked(&self, principal: &str, source: &str) -> bool {
        self.throttle.is_locked(principal, source)
    }

    /// Live entries in the **lock** table (G15 "表项有界" 的另一半：这条之前锁表大小
    /// 全仓不可读，所以 `locked.len() ≤ buckets.len() ≤ max_throttle_buckets` 里
    /// 只有右半边有观测面，r8 R8-W-3）。
    pub fn throttle_locks(&self) -> usize {
        self.throttle.locks()
    }

    /// Live per-source locks and the addresses currently spending their allowance
    /// (G15 的单源限额观测面)。
    pub fn throttle_source_locks(&self) -> usize {
        self.throttle.source_locks_live()
    }

    pub fn throttle_source_ledgers(&self) -> usize {
        self.throttle.source_ledgers()
    }

    /// The **only** place that compares the presented token against the config
    /// token, and the only place that advances `token_compares`. Folding the two
    /// together is what makes the counter a real witness: routing the comparison
    /// through anything else (e.g. `presented != self.token`) stops the counter and
    /// therefore goes red, which it did not while the increment sat on a separate
    /// line next to the call（r10 自查抓到的过度声明）.
    ///
    /// 更强的那一半其实是构建期给的：绕开这个函数直接比较，`token_eq` 就变成
    /// never-used，`warnings = "deny"` 下**编不过**（实测 F 变异）。反过来，把本函数
    /// **内部**的 `constant_time_eq` 换成 `!=` 不会被任何测试抓到——长度相关的时序
    /// 仍只能由 `constant_time_eq` 自己的单测加评审目视负责，别把计数当时序证明。
    fn token_eq(&mut self, presented: &str) -> bool {
        self.token_compares = self.token_compares.saturating_add(1);
        constant_time_eq(presented.as_bytes(), self.token.as_bytes())
    }

    /// How many times `authenticate` actually ran the constant-time token
    /// comparison. This counter exists to make contract sentences machine
    /// checkable instead of prose-only（评审 r1/r8 都登记过："没有任何断言约束
    /// authenticate 真的用 `constant_time_eq`"）：
    /// (1) 一次可比较令牌的尝试 ⇒ 恰好 +1；
    /// (2) 锁定/源锁短路掉的尝试 ⇒ **不**增加，这正是"锁内不做令牌比较"的证据。
    ///
    /// 删掉锁定预检会让这条与冻结期望 `token_comparisons_short_circuit_when_locked`
    /// 变红；试图绕开 `token_eq` 直接比较则根本编不过（dead code，见上面的 F 变异实测）。
    pub fn token_comparisons(&self) -> usize {
        self.token_compares
    }

    /// Read-only view of the shared send budget (probe/diagnostics).
    pub fn budget(&self) -> &SendBudget {
        &self.budget
    }

    /// Terminal-class (ssh/control) send. Never squeezed out by file traffic.
    /// 被挤掉的每一条文件类消息都会回冲它自己会话的在途额度（r2 NEW-2 第 1 点），
    /// 否则那个会话只能去 ack 一份它从未收到的页。
    pub fn send_terminal(&mut self, bytes: usize) -> FileResult<()> {
        // 清单必须**先回冲再看结果**：用 `?` 提前返回会把挤掉的消息连同清单一起
        // 丢掉，那些会话的额度就永久悬空（评审 r3 R3-NEW-1，本机无编译能力，
        // 由评审方的 std-only 复算件证实：弹 8 条后 inflight 64 而 budget 0）。
        let (evicted, outcome) = self.budget.push_terminal(bytes);
        for (sid, n) in evicted {
            if let Some(s) = self.sessions.get_mut(&sid) {
                s.inflight_bytes = s.inflight_bytes.saturating_sub(n);
            }
        }
        outcome
    }

    /// The transport flushed terminal-class bytes.
    pub fn settle_terminal(&mut self, bytes: usize) {
        self.budget.settle_terminal(bytes);
    }

    /// The peer acked `bytes` of file-class traffic from `session`: both the
    /// per-session in-flight ceiling and the shared budget are released here,
    /// and nowhere else (G18 pull-based download). 会话额度按**实际释放的字节**
    /// 回冲，不按请求量——整条消息才可能出队，部分 ack 不虚报。
    pub fn settle_file(&mut self, session: u64, bytes: usize) {
        let freed = self.budget.settle_file(session, bytes);
        if let Some(s) = self.sessions.get_mut(&session) {
            s.inflight_bytes = s.inflight_bytes.saturating_sub(freed);
        }
    }

    /// Un-acked file-class bytes for one session.
    pub fn inflight_bytes(&self, session: u64) -> usize {
        self.sessions
            .get(&session)
            .map(|s| s.inflight_bytes)
            .unwrap_or(0)
    }

    /// 不变量：会话的在途额度必须等于预算里替它占着的字节。挤占、ack、会话拆除
    /// 任一处漏了释放，这里就会背离（r2 NEW-2 的机器化判据）。
    pub fn inflight_matches_budget(&self, session: u64) -> bool {
        self.inflight_bytes(session) == self.budget.file_buffered_for(session)
    }

    /// Wire layer: charge one outbound file-class message whose serialized size
    /// only the caller knows (acks, list pages). 引擎不替它编数字——宁可要求
    /// 调用方显式过账，也不让预算在看不见的地方漏计（评审 F1）。
    pub fn send_file_message(&mut self, session: u64, bytes: usize) -> FileResult<()> {
        self.charge_file(session, bytes)
    }

    /// 流属于哪个 root（审计归因用；r6 WARN-1：`stage_chunk`/`ack_staged` 的
    /// 拒绝行过去写死 `root=""`，G21 要求的五字段就缺了一格）。
    fn stream_root(&self, session: u64, stream: u64) -> Option<String> {
        self.sessions
            .get(&session)
            .and_then(|s| s.streams.get(&stream))
            .map(|st| st.root.clone())
    }

    /// Charge one outbound file-class message: first against the shared SCTP
    /// budget (the transport-level truth), then against the per-session
    /// in-flight ceiling. A refusal is explicit (`QUEUE_FULL` / `CAPACITY`) and
    /// leaves no state behind, so the caller can retry after the peer acks.
    fn charge_file(&mut self, session: u64, bytes: usize) -> FileResult<()> {
        if bytes == 0 {
            return Ok(());
        }
        // 会话必须已存在：对未知会话过账会造出一条无归属、永不释放的预算条目
        // （r2 NEW-2 第 3 点）。
        let current = self.session(session)?.inflight_bytes;
        let ceiling = self.limits.max_inflight_bytes_per_session;
        // 共享预算先扣：两条上限同时满时，对外报的是"传输发不出去"（QUEUE_FULL），
        // 这才是调用方需要的信号；per-session 额度是第二道闸，报 CAPACITY。
        self.budget.push_file(session, bytes)?;
        // 过账之后的**每一条**早退都必须回滚预算（评审 r3 R3-W-1：旧写法只回滚
        // CAPACITY 那条，`?` 走掉的 OVERFLOW 会留下"占共享预算、不占会话额度"
        // 的条目，inflight_matches_budget 反向背离且没有释放路径）。
        let next = match current.checked_add(bytes) {
            Some(n) => n,
            None => {
                self.budget.unpush_file(session, bytes);
                return Err(FileError::new(code::OVERFLOW, "in-flight bytes overflow"));
            }
        };
        if next > ceiling {
            // 回滚刚刚记入预算的这一条：它没有出门，不能占额度。
            self.budget.unpush_file(session, bytes);
            return Err(FileError::new(
                code::CAPACITY,
                format!(
                    "per-session in-flight budget {ceiling} exhausted; \
                     ack outstanding pages before requesting more"
                ),
            ));
        }
        if let Some(s) = self.sessions.get_mut(&session) {
            s.inflight_bytes = next;
        }
        Ok(())
    }

    fn root(&self, name: &str) -> FileResult<&SandboxRoot> {
        self.roots
            .get(name)
            .ok_or_else(|| FileError::new(code::NOT_FOUND, format!("unknown root {name:?}")))
    }

    /// Constant-time token comparison plus lockout check (G15). A correct token
    /// during a lockout window is still refused: the lock is on the principal and
    /// the source, not on the guess.
    pub fn authenticate(
        &mut self,
        principal: &str,
        source: &str,
        presented: &str,
    ) -> FileResult<u64> {
        // `source` 在本批被升格成两样东西的凭证材料（`close_session` 的归属证明、
        // 单源额度的键），所以空串不能当身份用：把它当成一条正常失败会留下一整桶
        // ("", "") 的节流状态，谁都能往里灌失败、也谁都能替它"还清"。引擎不解析也不
        // 归一化传输地址（见 `FileLimits::max_failures_per_source` 与 G16 的前提段），
        // 但空值是唯一一种"必然无法验归属"的输入，直接在门外挡掉。
        if source.is_empty() {
            self.record(0, principal, "", "authenticate", "", code::AUTH_DENIED);
            return Err(FileError::new(
                code::AUTH_DENIED,
                "a peer transport address is required",
            ));
        }
        if self.throttle.is_locked(principal, source) {
            self.record(0, principal, "", "authenticate", "", code::THROTTLED);
            return Err(FileError::new(code::THROTTLED, "locked out"));
        }
        // 比较必须走 `token_eq`：计数点在**唯一**那个调用 `constant_time_eq` 的地方，
        // 所以"绕过它"与"少一次比较"是同一件事，测试红得下来（r10 自查：计数原先
        // 挂在比较之前的一行上，把 `constant_time_eq(...)` 换成 `!=` 仍然全绿，
        // 那句"换掉就会红"是过度声明）。
        if !self.token_eq(presented) {
            let locked = self.throttle.record_failure(principal, source);
            self.record(
                0,
                principal,
                "",
                "authenticate",
                "",
                if locked {
                    code::THROTTLED
                } else {
                    code::AUTH_DENIED
                },
            );
            return Err(FileError::new(
                if locked {
                    code::THROTTLED
                } else {
                    code::AUTH_DENIED
                },
                "token rejected",
            ));
        }
        self.throttle.succeed(principal, source);
        // 会话数必须是**准入**检查，不是只在 `validate()` 里比一下（评审 r2 NEW-4）：
        // 否则一个持有合法令牌的浏览器可以无限量开会话，每会话再开无限条流、
        // 每流一个 `.part`。G16/PRODUCT §18.2 把"并发会话数"列为有配额表的上界。
        if self.sessions.len() >= self.limits.max_sessions {
            self.record(0, principal, "", "authenticate", "", code::CAPACITY);
            return Err(FileError::new(
                code::CAPACITY,
                format!(
                    "max_sessions {} reached; close an idle file session first",
                    self.limits.max_sessions
                ),
            ));
        }
        let held_by_peer = self
            .sessions
            .values()
            .filter(|s| s.source == source)
            .count();
        if held_by_peer >= self.limits.max_browser_sessions {
            self.record(0, principal, "", "authenticate", "", code::CAPACITY);
            return Err(FileError::new(
                code::CAPACITY,
                format!(
                    "peer {source:?} already holds {held_by_peer} of {} browser file sessions",
                    self.limits.max_browser_sessions
                ),
            ));
        }
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.insert(
            id,
            FileSession {
                id,
                principal: principal.to_string(),
                source: source.to_string(),
                inflight_bytes: 0,
                streams: BTreeMap::new(),
                last_activity: Instant::now(),
                recycled: false,
            },
        );
        self.record(id, principal, "", "authenticate", "", "OK");
        Ok(id)
    }

    /// Close one file session. The caller must present the **same transport
    /// address** the session was authenticated from; otherwise the call is
    /// indistinguishable from closing an unknown id.
    ///
    /// 历史：r2 N-8 的处置曾是"`source` **故意不是参数**"——因为那时唯一的用途是
    /// "拆会话顺手清节流桶"，让调用方传地址等于让别人替别人清账。本批把它反过来：
    /// 参数回来了，但用途变成**验证归属**，而节流状态彻底不从这条路清（见
    /// `Throttle::succeed` 的三段历史）。为什么必须反过来（r8 R8-W-2 追到的根因入口）：
    /// 会话号由 `next_session` 顺序自增、可枚举，在这个检查之前 `close_session(id)`
    /// 会**删掉别人的 `.part` 暂存文件**并释放其发送预算——只猜到一个整数就能打断
    /// 别人正在进行的上传，"替别人清计数"的后门也挂在这同一个入口上。
    ///
    /// 三条必须一起读的口径与残余：
    /// - **同形性只管返回值与审计行**：未知 id 与"存在但不属于你"两分支的
    ///   `record` 六格入参、返回码、消息字面量都相同（顺序敏感：审计行必须写在把会话
    ///   `insert` 回去**之前**，否则 `record` 回查会话补 principal 就泄露了主体名）。
    ///   这不是"完全不可区分"——被拒分支多一次 `sessions.insert`，时序上未必同形，
    ///   地址比较本身也不是常数时间（这里与令牌比较口径不同：泄露的是"这个 id 属于
    ///   这个地址"，而调用方已经知道自己在猜谁的地址；令牌那条不一样）。
    /// - **射程只到"替别人关会话"这一支**：同一个 crate 里 `abort_upload`（删已暂存
    ///   字节）等动词仍只看 session id，不做归属证明，同类破坏面原样保留；G16 明写了
    ///   这一条边界，别把这里读成"所有自增号入口都关上了"。
    /// - **引擎不归一化地址**：auth 与 close 两处必须由**同一个** transport-address
    ///   供给点给出同一字符串，否则合法所有者关不掉自己的会话（等 `idle_timeout`）；
    ///   空串在 `authenticate` 就被拒。带不带端口、IPv6 方括号/zone 这类表示差异
    ///   会同时影响归属检查、单源额度与 per-peer 配额——M2 接线时必须核（G16 前提段）。
    pub fn close_session(&mut self, session: u64, source: &str) -> FileResult<()> {
        let Some(s) = self.sessions.remove(&session) else {
            // 未知会话号也要留一行：否则"关不掉"在审计里是隐形的，G21 说的
            // "漏记在结构上不可发生"就只对已知会话成立（评审 r5 N-8）。
            let label = session.to_string();
            self.record(session, "", "", "close_session", &label, code::NOT_FOUND);
            return Err(FileError::new(
                code::NOT_FOUND,
                "no such file session for this peer",
            ));
        };
        if s.source != source {
            // 顺序要紧：`record` 在调用方留空 principal 时会**回查会话**补上归属
            // （F4 那一片为审计归因加的），所以必须先落审计行、再把会话放回去。
            // 否则"不存在的 id"那行的 principal 是空串，而"存在但不属于你"那行会被
            // 补成受害者主体名 ⇒ 这条入口自己变成会话枚举的 oracle。测试
            // `closing_another_peers_session_is_refused_and_leaves_it_intact` 就是在
            // 我第一版实现上把这一格抓红的（左 "" 右 "victim"）。
            let label = session.to_string();
            self.record(session, "", "", "close_session", &label, code::NOT_FOUND);
            // 原样放回：没删会话、没删 `.part`、没释放预算、没碰节流状态。
            self.sessions.insert(session, s);
            return Err(FileError::new(
                code::NOT_FOUND,
                "no such file session for this peer",
            ));
        }
        for st in s.streams.into_values() {
            let _ = std::fs::remove_file(&st.part_path);
        }
        // 会话没了，它占着的预算条目必须一起释放，否则一次断线就把全节点
        // 文件类发送预算永久钉死（r2 NEW-2 第 2 点）。
        self.budget.release_session(session);
        // 节流状态**一个都不清**（r7 R7-W-2 → r8 R8-W-2 的两轮修正，完整理由
        // 写在 `Throttle::succeed` 上）：拆除既不能删锁（=解锁），也不能删计数
        // （=把计数按定义钉在阈值之下，锁永远武装不了）。
        self.record(session, &s.principal, "", "close_session", "", "OK");
        Ok(())
    }

    /// Sweep idle sessions (G21). Returns recycled ids.
    pub fn sweep_idle(&mut self, now: Instant) -> Vec<u64> {
        let timeout = self.limits.idle_timeout;
        let mut out = Vec::new();
        for s in self.sessions.values_mut() {
            if now.saturating_duration_since(s.last_activity) > timeout {
                s.recycled = true;
                for st in s.streams.values() {
                    let _ = std::fs::remove_file(&st.part_path);
                }
                s.streams.clear();
                out.push(s.id);
            }
        }
        for id in &out {
            if let Some(s) = self.sessions.remove(id) {
                self.budget.release_session(s.id);
                self.record(s.id, &s.principal, "", "idle_recycle", "", code::IDLE);
            }
        }
        out
    }

    fn touch(&mut self, session: u64) -> FileResult<()> {
        let s = self.session_mut(session)?;
        s.last_activity = Instant::now();
        Ok(())
    }

    fn session(&self, session: u64) -> FileResult<&FileSession> {
        self.sessions
            .get(&session)
            .ok_or_else(|| FileError::new(code::NOT_FOUND, format!("no such session {session}")))
    }

    fn session_mut(&mut self, session: u64) -> FileResult<&mut FileSession> {
        self.sessions
            .get_mut(&session)
            .ok_or_else(|| FileError::new(code::NOT_FOUND, format!("no such session {session}")))
    }

    /// Paged listing (G17). Entries are read lazily up to the page cap **and**
    /// up to the serialized-ack ceiling, so a 100k-entry directory cannot be
    /// materialized as one ack and a directory of long names cannot produce an
    /// oversized ack either (评审 WARN：旧实现只数条目，不看字节).
    pub fn list(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: usize,
    ) -> FileResult<ListPage> {
        let outcome = self.list_inner(session, root, rel, offset);
        match &outcome {
            Ok(_) => self.record(session, "", root, "list", rel, "OK"),
            Err(e) => self.record(session, "", root, "list", rel, e.code),
        }
        outcome
    }

    fn list_inner(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: usize,
    ) -> FileResult<ListPage> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_local_io()?;
        let abs = r.resolve(rel)?;
        let mut rd = std::fs::read_dir(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        let cap = self.limits.max_entries_per_page;
        let ack_budget = self.limits.max_ack_bytes;
        let mut ack_bytes = LIST_ACK_ENVELOPE_BYTES;
        let mut entries = Vec::with_capacity(cap.min(64));
        let mut idx = 0usize;
        let mut truncated = false;
        loop {
            let next = match rd.next() {
                Some(Ok(e)) => e,
                Some(Err(e)) => return Err(FileError::new(code::NOT_FOUND, e.to_string())),
                None => break,
            };
            if idx < offset {
                idx += 1;
                continue;
            }
            let raw_name = next.file_name().to_string_lossy().replace('\\', "/");
            // 条目数上限与 ack 字节上限，谁先到谁截断；两者都必须显式报 truncated。
            if entries.len() >= cap
                || ack_bytes + ENTRY_ACK_OVERHEAD_BYTES + raw_name.len() > ack_budget
            {
                truncated = true;
                break;
            }
            // 只用 symlink_metadata 的结果：`next.metadata()` 会**跟随**链接，
            // 于是一个悬空链接就能让整页以 NOT_FOUND 失败（本地用户放一个坏链接
            // 即可让该目录不可浏览），而且 `is_dir` 会取自 root 外的目标，
            // 把一个 root 外目录的存在性当 oracle 回给客户端（评审 r2 W-2）。
            let link = next
                .path()
                .symlink_metadata()
                .map_err(|e| FileError::new(code::NOT_FOUND, e.to_string()))?;
            let is_link = link.file_type().is_symlink();
            ack_bytes += ENTRY_ACK_OVERHEAD_BYTES + raw_name.len();
            entries.push(Entry {
                name: raw_name,
                is_dir: link.is_dir(),
                is_symlink: is_link,
                size: if is_link { 0 } else { link.len() },
            });
            idx += 1;
        }
        // 字节上限把一个"应该有进展"的页压成 0 条目时，返回空页等于让客户端
        // 永远停在同一个 `next_offset == offset`（G17 的单调性被静默破坏，评审 r5
        // R5-W-3）。这种情况必须显式拒，而不是假装"这一页是空的但没读完"。
        if truncated && entries.is_empty() {
            return Err(FileError::new(
                code::PAGE_TOO_LARGE,
                format!(
                    "the next entry of {rel:?} does not fit max_ack_bytes {ack_budget} \
                     (envelope {ack_bytes} + entry cost); raise max_ack_bytes or list a \
                     directory with shorter names — returning an empty page would stall \
                     next_offset at {offset}"
                ),
            ));
        }
        // G16/W-11：`list` 是引擎能自己算出序列化成本的动词——上面的截断逻辑已经
        // 累计了 `ack_bytes`，这里就按它过账。预算满时报 `QUEUE_FULL` 且**不回滚**
        // 目录扫描：目录读成功是事实，只是这一页发不出去，调用方排空后重试即可。
        self.charge_file(session, ack_bytes)?;
        Ok(ListPage {
            next_offset: offset + entries.len(),
            entries,
            truncated,
            is_complete_list: !truncated,
        })
    }

    /// Read one page (G18/G20). `offset + max_bytes` uses checked arithmetic;
    /// `max_bytes` above the configured page ceiling is refused, not clamped.
    ///
    /// 审计在这一层统一落账：无论成功还是任何一条拒绝路径，都恰好一行
    /// （G21）。放在包装层而不是散在各 return 前，是为了让"漏记"在结构上
    /// 不可能——评审指出旧写法删掉任意一处 `record` 测试都不会红。
    pub fn read_page(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: u64,
        max_bytes: usize,
    ) -> FileResult<DataPage> {
        let outcome = self.read_page_inner(session, root, rel, offset, max_bytes);
        match &outcome {
            Ok(_) => self.record(session, "", root, "read", rel, "OK"),
            Err(e) => self.record(session, "", root, "read", rel, e.code),
        }
        outcome
    }

    fn read_page_inner(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: u64,
        max_bytes: usize,
    ) -> FileResult<DataPage> {
        self.touch(session)?;
        if max_bytes == 0 || max_bytes > self.limits.chunk_bytes {
            // 0 字节请求会让 `next_offset == offset`，破坏 G17 的"next_offset 单调"
            // （客户端会永远停在同一页），所以显式拒而不是返回空页（评审 r2 W-4）。
            return Err(FileError::new(
                code::PAGE_TOO_LARGE,
                format!(
                    "requested {max_bytes} must be in 1..=chunk_bytes {}",
                    self.limits.chunk_bytes
                ),
            ));
        }
        let r = self.root(root)?.clone();
        r.require_local_io()?;
        let abs = r.resolve(rel)?;
        let end = offset
            .checked_add(max_bytes as u64)
            .ok_or_else(|| FileError::new(code::OVERFLOW, "offset + max_bytes overflow"))?;
        let key = abs.to_string_lossy().to_string();
        self.handles.acquire(session, &key)?;
        let opened = std::fs::File::open(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")));
        let mut f = match opened {
            Ok(f) => f,
            Err(e) => {
                self.handles.release(session, &key);
                return Err(e);
            }
        };
        // Post-open re-verify (G13): the path we actually opened must still be
        // inside the root and still not a symlink.
        if let Err(e) = r.reverify(&abs, rel) {
            self.handles.release(session, &key);
            return Err(e);
        }
        let len = match f.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                self.handles.release(session, &key);
                return Err(FileError::new(code::NOT_FOUND, e.to_string()));
            }
        };
        if len == 0 || offset >= len {
            self.handles.release(session, &key);
            return Ok(DataPage {
                bytes: Vec::new(),
                offset,
                next_offset: offset,
                eof: true,
            });
        }
        let want = (end.min(len)).saturating_sub(offset) as usize;
        let mut buf = vec![0u8; want];
        if let Err(e) = f.seek(SeekFrom::Start(offset)) {
            self.handles.release(session, &key);
            return Err(FileError::new(code::NOT_FOUND, e.to_string()));
        }
        let read = match read_exact_or_partial(&mut f, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                self.handles.release(session, &key);
                return Err(FileError::new(code::NOT_FOUND, e.to_string()));
            }
        };
        buf.truncate(read);
        let next = offset + read as u64;
        let eof = next >= len;
        // 同步读完即释放：`File` 在这里离开作用域，注册表也必须在这里一起结束。
        // 只在 eof 时释放会让每个非末页驻留一个"活句柄"，正是 V1 每片一条流的翻版。
        self.handles.release(session, &key);
        // 页字节走共享预算：满则显式拒绝（拉式协议下客户端必须先 ack 上一页）。
        self.charge_file(session, buf.len())?;
        Ok(DataPage {
            bytes: buf,
            offset,
            next_offset: next,
            eof,
        })
    }

    /// Open an upload stream. The **server** issues the id (G16) and the `.part`
    /// name carries a per-stream nonce so two clients cannot collide on it (G14).
    pub fn open_upload(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        declared_len: Option<u64>,
    ) -> FileResult<u64> {
        let outcome = self.open_upload_inner(session, root, rel, declared_len);
        match &outcome {
            Ok(_) => self.record(session, "", root, "open_upload", rel, "OK"),
            Err(e) => self.record(session, "", root, "open_upload", rel, e.code),
        }
        outcome
    }

    fn open_upload_inner(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        declared_len: Option<u64>,
    ) -> FileResult<u64> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        if let Some(n) = declared_len {
            if n > self.limits.max_upload_bytes {
                return Err(FileError::new(
                    code::CAPACITY,
                    format!(
                        "declared {n} > max_upload_bytes {}",
                        self.limits.max_upload_bytes
                    ),
                ));
            }
        }
        // resolve() 不再对缺失路径提前返回：目标不存在是上传的正常情况，
        // 而 `..`/符号链接/越界必须在这里就拒，绝不退化到未校验的 join。
        let abs = r.resolve(rel)?;
        r.reverify_parent(&abs, rel)?;
        // Refuse when the final target already exists: publishing must not
        // replace it (G14), so we also refuse to start a stream that cannot land.
        if abs.exists() {
            return Err(FileError::new(
                code::EXISTS,
                format!("{rel:?} already exists"),
            ));
        }
        let id = self.next_stream;
        self.next_stream += 1;
        let part = part_path(&abs, id);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&part)
            .map_err(|e| {
                // 评审 r3 N-3（原 r2 N-3）：预置同名/链接的 `.part` 被拒是**授权面**
                // 问题，过去一律记成 CAPACITY_UNAVAILABLE，审计行跟着归因错。
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    FileError::new(
                        code::EXISTS,
                        format!("part file name was already taken: {e}"),
                    )
                } else {
                    FileError::new(code::CAPACITY, format!("cannot create part file: {e}"))
                }
            })?;
        let s = self.session_mut(session)?;
        s.streams.insert(
            id,
            UploadStream {
                id,
                session,
                root: root.to_string(),
                rel: rel.to_string(),
                staged: 0,
                declared_len,
                hasher: Sha256::new(),
                hashed_bytes: 0,
                rehash_bytes: 0,
                part_path: part.clone(),
                file,
                last_activity: Instant::now(),
            },
        );
        s.last_activity = Instant::now();
        Ok(id)
    }

    /// Stage one chunk. The returned ack is **contiguous staged bytes** (G18):
    /// a chunk at the current prefix appends and advances; a fully duplicate page
    /// must match byte-for-byte and advances nothing; a jump or an overlapping
    /// mismatch is refused and the prefix is never rewritten.
    ///
    /// 只记**拒绝**：逐片成功行会把有界审计环冲满（一个 2 GiB 上传就是 32768 行），
    /// 而成功路径由"连续前缀 ack + commit 行"完整覆盖（G21 要的是可归因，不是刷屏）。
    pub fn stage_chunk(
        &mut self,
        session: u64,
        stream: u64,
        offset: u64,
        bytes: &[u8],
    ) -> FileResult<u64> {
        let outcome = self.stage_chunk_inner(session, stream, offset, bytes);
        if let Err(e) = &outcome {
            let label = stream.to_string();
            let root = self.stream_root(session, stream).unwrap_or_default();
            self.record(session, "", &root, "stage_chunk", &label, e.code);
        }
        outcome
    }

    fn stage_chunk_inner(
        &mut self,
        session: u64,
        stream: u64,
        offset: u64,
        bytes: &[u8],
    ) -> FileResult<u64> {
        self.touch(session)?;
        // Hoist limit reads before borrowing `self.sessions` mutably.
        let chunk_limit = self.limits.chunk_bytes;
        let max_upload = self.limits.max_upload_bytes;
        let rehash_budget = self.limits.max_rehash_bytes_per_stream;
        if bytes.len() > chunk_limit {
            return Err(FileError::new(
                code::PAGE_TOO_LARGE,
                format!("chunk {} > chunk_bytes {chunk_limit}", bytes.len()),
            ));
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| FileError::new(code::OVERFLOW, "offset + len overflow"))?;
        let s = self.session_mut(session)?;
        let st = s
            .streams
            .get_mut(&stream)
            .ok_or_else(|| FileError::new(code::NOT_FOUND, format!("no such stream {stream}")))?;
        st.last_activity = Instant::now();
        if offset == st.staged {
            if let Some(n) = st.declared_len {
                if end > n {
                    return Err(FileError::new(
                        code::INTEGRITY,
                        format!("chunk would exceed declared length {n}"),
                    ));
                }
            }
            if end > max_upload {
                return Err(FileError::new(
                    code::CAPACITY,
                    "upload exceeds max_upload_bytes",
                ));
            }
            st.file
                .seek(SeekFrom::End(0))
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            st.file
                .write_all(bytes)
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            st.file
                .flush()
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            // 顺序到达的字节直接进摘要：这部分成本已经由 `max_upload_bytes` 封顶，
            // 再用 rehash 预算去截断它，等于让"大于预算的工件永远无法带摘要发布"
            // （评审 WARN：把回读预算误用成验证门）。
            st.hasher.update(bytes);
            st.hashed_bytes += bytes.len() as u64;
            st.staged = end;
            s.last_activity = Instant::now();
            return Ok(st.staged);
        }
        if offset < st.staged {
            // Replay of already-staged prefix: re-read and compare, byte-exact.
            if end > st.staged {
                return Err(FileError::new(
                    code::INTEGRITY,
                    format!(
                        "partially overlapping page {}..{} against staged prefix {}",
                        offset, end, st.staged
                    ),
                ));
            }
            // 这才是 rehash 预算真正覆盖的成本：恶意客户端反复重放已暂存的页，
            // 服务端每次都从磁盘回读。超过预算就显式拒绝，不是静默少算。
            let reread = st
                .rehash_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| FileError::new(code::OVERFLOW, "rehash accounting overflow"))?;
            if reread > rehash_budget {
                return Err(FileError::new(
                    code::CAPACITY,
                    format!(
                        "duplicate-page re-read budget {rehash_budget} exceeded \
                         (replayed {reread} bytes)"
                    ),
                ));
            }
            st.rehash_bytes = reread;
            let mut buf = vec![0u8; bytes.len()];
            st.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            let n = read_exact_or_partial(&mut st.file, &mut buf)
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            if n != bytes.len() || buf != bytes {
                return Err(FileError::new(
                    code::INTEGRITY,
                    "duplicate page does not match the staged bytes",
                ));
            }
            return Ok(st.staged);
        }
        Err(FileError::new(
            code::INTEGRITY,
            format!(
                "jump: offset {offset} ahead of contiguous prefix {}",
                st.staged
            ),
        ))
    }

    /// Ack after staging: contiguous bytes, capped so the ack itself can never
    /// exceed the send budget (G17). 成功不写审计行（逐片 ack 会灌满环，与
    /// `stage_chunk` 同一口径），拒绝必须写。
    pub fn ack_staged(&mut self, session: u64, stream: u64) -> FileResult<u64> {
        let outcome = (|| -> FileResult<u64> {
            let s = self.session(session)?;
            let st = s.streams.get(&stream).ok_or_else(|| {
                FileError::new(code::NOT_FOUND, format!("no such stream {stream}"))
            })?;
            Ok(st.staged)
        })();
        if let Err(e) = &outcome {
            let label = stream.to_string();
            let root = self.stream_root(session, stream).unwrap_or_default();
            self.record(session, "", &root, "ack_staged", &label, e.code);
        }
        outcome
    }

    /// Commit: verify length and (when within the rehash budget) the digest, then
    /// publish with a **non-overwriting** hard link (G14/G18).
    ///
    /// 审计在包装层统一落一行（成功用发布后的路径，拒绝用流里记录的 rel），
    /// 这样任何一条提前 return 的拒绝路径都不可能漏记。
    pub fn commit_upload(
        &mut self,
        session: u64,
        root: &str,
        stream: u64,
        expected_sha256: Option<[u8; 32]>,
    ) -> FileResult<String> {
        let audit_rel = self
            .sessions
            .get(&session)
            .and_then(|s| s.streams.get(&stream))
            .map(|st| st.rel.clone())
            .unwrap_or_else(|| format!("stream {stream}"));
        let outcome = self.commit_upload_inner(session, root, stream, expected_sha256);
        match &outcome {
            Ok(published) => self.record(session, "", root, "commit", published, "OK"),
            Err(e) => self.record(session, "", root, "commit", &audit_rel, e.code),
        }
        outcome
    }

    fn commit_upload_inner(
        &mut self,
        session: u64,
        root: &str,
        stream: u64,
        expected_sha256: Option<[u8; 32]>,
    ) -> FileResult<String> {
        self.touch(session)?;
        // 流绑死在打开它的那个 root 上（评审 r2 NEW-1）：提交时换一个 root 参数
        // 曾可以把可写根上开的流发布进 `read_only` 根，或把 SFTP 根的远端路径
        // 丢给本地解析器 `hard_link`。授权面只有 G13 的 root 一个。
        let opened_on = {
            let s = self.session(session)?;
            let st = s.streams.get(&stream).ok_or_else(|| {
                FileError::new(code::NOT_FOUND, format!("no such stream {stream}"))
            })?;
            st.root.clone()
        };
        if opened_on != root {
            return Err(FileError::new(
                code::OUTSIDE_ROOT,
                format!(
                    "stream {stream} was opened on root {opened_on:?}; \
                     refusing to publish through {root:?}"
                ),
            ));
        }
        let r = self.root(root)?.clone();
        r.require_writable()?;
        r.require_local_io()?;
        let (rel, part, file, digest_complete, digest) = {
            let s = self.session_mut(session)?;
            let st = s.streams.get_mut(&stream).ok_or_else(|| {
                FileError::new(code::NOT_FOUND, format!("no such stream {stream}"))
            })?;
            if let Some(n) = st.declared_len {
                if st.staged != n {
                    return Err(FileError::new(
                        code::INTEGRITY,
                        format!("staged {} != declared length {n}", st.staged),
                    ));
                }
            }
            // 发布前唯一一次 fsync：`.part` 落盘后才允许 hard_link 曝光，
            // 否则"已提交"的文件可能是零长度（评审 WARN：ack 不得自称 durable）。
            st.file
                .sync_all()
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            let digest_complete = st.hashed_bytes >= st.staged;
            let digest = st.hasher.clone().finalize();
            let mut out = [0u8; 32];
            if digest_complete {
                out.copy_from_slice(&digest);
            }
            (
                st.rel.clone(),
                st.part_path.clone(),
                st.file
                    .try_clone()
                    .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?,
                digest_complete,
                out,
            )
        };
        if let Some(exp) = expected_sha256 {
            if !digest_complete {
                return Err(FileError::new(
                    code::CAPACITY,
                    "digest requested but rehash budget could not cover the stream",
                ));
            }
            if digest != exp {
                self.discard_stream(session, stream);
                return Err(FileError::new(code::INTEGRITY, "sha256 mismatch"));
            }
        }
        let target = match r.resolve(&rel) {
            Ok(p) => p,
            Err(e) => {
                self.discard_stream(session, stream);
                return Err(e);
            }
        };
        if let Err(e) = r.reverify_parent(&target, &rel) {
            // 发布前的目录级复核失败：这条流不可能落地，清掉暂存物再返回。
            self.discard_stream(session, stream);
            return Err(e);
        }
        // Non-overwriting publish. `hard_link` fails if the destination exists,
        // which is the std-only equivalent of the intent N3-4 describes.
        if let Err(e) = std::fs::hard_link(&part, &target) {
            let err = if e.kind() == std::io::ErrorKind::AlreadyExists {
                FileError::new(
                    code::EXISTS,
                    format!("{rel:?} exists; refusing to overwrite"),
                )
            } else {
                FileError::new(code::CAPACITY, format!("publish failed: {e}"))
            };
            // G14：被拒绝的发布不留 `.part`。这里与"页级拒绝"故意不同——后者要保留
            // 已承认前缀供续传（G18），而"目标已存在"这条流永远不可能成功，
            // 留着只会变成无人负责的中转字节（E4 场景实测抓到的正是这个残留）。
            drop(file);
            self.discard_stream(session, stream);
            return Err(err);
        }
        drop(file);
        let _ = std::fs::remove_file(&part);
        self.session_mut(session)?.streams.remove(&stream);
        Ok(r.display_rel(&target))
    }

    /// Discard a stream and its staged bytes. Used internally by refusals that
    /// already write their own audit line (commit), so it does not record here.
    fn discard_stream(&mut self, session: u64, stream: u64) {
        if let Some(s) = self.sessions.get_mut(&session) {
            if let Some(st) = s.streams.remove(&stream) {
                let _ = std::fs::remove_file(&st.part_path);
            }
        }
    }

    /// Client-initiated abort: destructive (it deletes already-staged bytes), so
    /// it must leave an audit line like every other client verb (评审 r2 W-5).
    pub fn abort_upload(&mut self, session: u64, stream: u64) {
        let located = self
            .sessions
            .get(&session)
            .and_then(|s| s.streams.get(&stream))
            .map(|st| (st.root.clone(), st.rel.clone()));
        self.discard_stream(session, stream);
        match located {
            Some((root, rel)) => self.record(session, "", &root, "abort_upload", &rel, "OK"),
            None => {
                let label = stream.to_string();
                self.record(session, "", "", "abort_upload", &label, code::NOT_FOUND);
            }
        }
    }

    pub fn mkdir(&mut self, session: u64, root: &str, rel: &str) -> FileResult<()> {
        let outcome = self.mkdir_inner(session, root, rel);
        match &outcome {
            Ok(_) => self.record(session, "", root, "mkdir", rel, "OK"),
            Err(e) => self.record(session, "", root, "mkdir", rel, e.code),
        }
        outcome
    }

    fn mkdir_inner(&mut self, session: u64, root: &str, rel: &str) -> FileResult<()> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        // The target may not exist yet; every existing component (including the
        // parent) must resolve inside the root without traversing any symlink,
        // and the target itself must not already be a symlink.
        let abs = r.resolve(rel)?;
        r.reverify_ancestor(&abs, rel)?;
        if let Ok(meta) = std::fs::symlink_metadata(&abs) {
            if meta.file_type().is_symlink() {
                return Err(FileError::new(
                    code::SYMLINK_ESCAPE,
                    format!("{rel:?} is already a symlink"),
                ));
            }
        }
        std::fs::create_dir_all(&abs)
            .map_err(|e| FileError::new(code::CAPACITY, format!("mkdir {rel:?}: {e}")))?;
        Ok(())
    }

    /// Remove one entry; recursion is bounded to the root and refuses to follow
    /// any symlink (G13). `remove_tree` is only ever called with paths
    /// that resolved inside the root component-by-component.
    pub fn remove(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        recursive: bool,
    ) -> FileResult<usize> {
        let outcome = self.remove_inner(session, root, rel, recursive);
        match &outcome {
            Ok(_) => self.record(session, "", root, "remove", rel, "OK"),
            Err(e) => self.record(session, "", root, "remove", rel, e.code),
        }
        outcome
    }

    fn remove_inner(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        recursive: bool,
    ) -> FileResult<usize> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        let abs = r.resolve(rel)?;
        let meta = std::fs::symlink_metadata(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(FileError::new(
                code::SYMLINK_ESCAPE,
                format!("{rel:?} is a symlink"),
            ));
        }
        let mut removed = 0usize;
        if meta.is_dir() {
            if !recursive {
                if let Err(e) = std::fs::remove_dir(&abs) {
                    return Err(FileError::new(code::CAPACITY, e.to_string()));
                }
                removed += 1;
            } else {
                removed += self.remove_tree(&r, &abs, rel)?;
            }
        } else if let Err(e) = std::fs::remove_file(&abs) {
            return Err(FileError::new(code::CAPACITY, e.to_string()));
        } else {
            removed += 1;
        }
        Ok(removed)
    }

    fn remove_tree(&mut self, r: &SandboxRoot, dir: &Path, rel: &str) -> FileResult<usize> {
        let mut count = 0usize;
        let rd = std::fs::read_dir(dir)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        for e in rd.flatten() {
            let child_rel = format!("{rel}/{}", e.file_name().to_string_lossy());
            // Re-resolve through the sandbox rules: anything that escapes, or is
            // a symlink, is refused *before* deleting.
            let checked = r.resolve(&child_rel)?;
            let meta = std::fs::symlink_metadata(&checked)
                .map_err(|er| FileError::new(code::NOT_FOUND, er.to_string()))?;
            if meta.file_type().is_symlink() {
                return Err(FileError::new(
                    code::SYMLINK_ESCAPE,
                    format!("refusing to recurse through symlink {child_rel:?}"),
                ));
            }
            if meta.is_dir() {
                count += self.remove_tree(r, &checked, &child_rel)?;
            } else {
                std::fs::remove_file(&checked)
                    .map_err(|er| FileError::new(code::CAPACITY, er.to_string()))?;
                count += 1;
            }
        }
        std::fs::remove_dir(dir).map_err(|er| FileError::new(code::CAPACITY, er.to_string()))?;
        count += 1;
        Ok(count)
    }

    pub fn rename(&mut self, session: u64, root: &str, from: &str, to: &str) -> FileResult<()> {
        let outcome = self.rename_inner(session, root, from, to);
        match &outcome {
            // 审计行的 rel 记源路径；目标在错误消息里（一条操作只留一行）。
            Ok(_) => self.record(session, "", root, "rename", from, "OK"),
            Err(e) => self.record(session, "", root, "rename", from, e.code),
        }
        outcome
    }

    fn rename_inner(&mut self, session: u64, root: &str, from: &str, to: &str) -> FileResult<()> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        let src = r.resolve(from)?;
        let dst = r.resolve(to)?;
        r.reverify(&src, from)?;
        r.reverify_parent(&dst, to)?;
        if dst.exists() {
            return Err(FileError::new(code::EXISTS, format!("{to:?} exists")));
        }
        // `rename(2)` 的语义是**静默替换**，所以"先 exists 再 rename"在两个会话之间
        // （或会话与本地写者之间）存在窗口，目标一出现就覆盖原字节（评审 r2 W-3）。
        // 文件走原子路径：`hard_link` 对已存在目标必失败，成功再删源名；
        // 删源失败就回滚新名，绝不留下两个指向同一数据的名字。
        let src_is_dir = std::fs::metadata(&src)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{from:?}: {e}")))?
            .is_dir();
        if !src_is_dir {
            if let Err(e) = std::fs::hard_link(&src, &dst) {
                return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
                    FileError::new(
                        code::EXISTS,
                        format!("{to:?} exists; refusing to overwrite"),
                    )
                } else {
                    FileError::new(code::CAPACITY, format!("rename link failed: {e}"))
                });
            }
            if let Err(e) = std::fs::remove_file(&src) {
                let _ = std::fs::remove_file(&dst);
                return Err(FileError::new(
                    code::CAPACITY,
                    format!("rename unlink failed, rolled back: {e}"),
                ));
            }
            return Ok(());
        }
        // 目录：std 下拿不到"目标存在即失败"的原子改名（`hard_link` 对目录失败），
        // 这个窗口是**声明过的残余**，见 MODULE.md G13/PRODUCT §18.4——目录改名可能
        // 覆盖并发创建的同名目标，不提供无覆盖保证。
        std::fs::rename(&src, &dst)
            .map_err(|e| FileError::new(code::CAPACITY, format!("rename failed: {e}")))?;
        Ok(())
    }

    pub fn stat(&mut self, session: u64, root: &str, rel: &str) -> FileResult<Entry> {
        let outcome = self.stat_inner(session, root, rel);
        match &outcome {
            // 成功同样留一行：旧实现只记拒绝，"谁看了哪个文件"查不出来。
            Ok(_) => self.record(session, "", root, "stat", rel, "OK"),
            Err(e) => self.record(session, "", root, "stat", rel, e.code),
        }
        outcome
    }

    fn stat_inner(&mut self, session: u64, root: &str, rel: &str) -> FileResult<Entry> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_local_io()?;
        let abs = r.resolve(rel)?;
        let meta = std::fs::symlink_metadata(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(FileError::new(
                code::SYMLINK_ESCAPE,
                format!("{rel:?} is a symlink"),
            ));
        }
        Ok(Entry {
            name: rel.to_string(),
            is_dir: meta.is_dir(),
            is_symlink: false,
            size: meta.len(),
        })
    }

    /// Every operation, including refusals, leaves one audit line (G21).
    ///
    /// 日志本身是**有界**的，而且是**字节**有界（评审 r5 R5-W-4）：行数封顶
    /// `AUDIT_CAPACITY`，每个调用方可控字段裁到 `AUDIT_FIELD_MAX_BYTES` 并带
    /// `[+NB]` 截断标记——只写"行数有界"是不成立的，因为 `principal` 在令牌
    /// 校验之前就被写下、`rel` 由调用方给，未认证者本可以把每行写成任意大。
    /// 超出容量时丢最旧的一条并累加 `audit_dropped`，丢弃本身可观测，不是静默的。
    fn record(
        &mut self,
        session: u64,
        principal: &str,
        root: &str,
        action: &'static str,
        rel: &str,
        result_code: &str,
    ) {
        // 审计行必须带真实 principal：调用点传空串时从会话解析，
        // 否则拒绝记录只有会话号，事后无法归因（G21"可审计的拒绝"）。
        let principal = if principal.is_empty() {
            self.sessions
                .get(&session)
                .map(|s| s.principal.clone())
                .unwrap_or_default()
        } else {
            principal.to_string()
        };
        if self.audit.len() >= AUDIT_CAPACITY {
            self.audit.pop_front();
            self.audit_dropped += 1;
        }
        self.audit.push_back(AuditRecord {
            session,
            principal: bounded_label(&principal, AUDIT_FIELD_MAX_BYTES),
            root: bounded_label(root, AUDIT_FIELD_MAX_BYTES),
            action,
            rel: bounded_label(rel, AUDIT_FIELD_MAX_BYTES),
            result_code: result_code.to_string(),
        });
    }
}

impl SandboxRoot {
    /// Verify the *deepest existing ancestor* of a create target resolves inside
    /// the root and is not a symlink. `mkdir` needs this rather than
    /// [`reverify_parent`]: it creates a whole chain (`a/b/c`), so the immediate
    /// parent legitimately does not exist yet.
    ///
    /// 这是 F4 修复的配套一件：`resolve` 不再截断缺失路径之后，"父目录必须已存在"
    /// 的复核会把 `mkdir a/b` 一起拒掉（Linux 实测红过一条，见 green evidence）。
    /// 组件级检查仍然成立——`resolve` 已经逐段拒过符号链接。
    pub fn reverify_ancestor(&self, abs: &Path, rel: &str) -> FileResult<()> {
        let mut cur = abs.to_path_buf();
        loop {
            match std::fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(FileError::new(
                            code::SYMLINK_ESCAPE,
                            format!("ancestor of {rel:?} is a symlink: {cur:?}"),
                        ));
                    }
                    let canon = cur
                        .canonicalize()
                        .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
                    return Self::ensure_within(&self.canonical, &canon, rel);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !cur.pop() {
                        return Err(FileError::new(
                            code::OUTSIDE_ROOT,
                            format!("{rel:?} has no ancestor inside the root"),
                        ));
                    }
                }
                Err(e) => return Err(FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}"))),
            }
        }
    }

    /// Verify the *parent* directory of a create/publish target resolves inside
    /// the root and is not reached through a symlink. The final component may
    /// not exist yet, which is why this is separate from `reverify`.
    pub fn reverify_parent(&self, abs: &Path, rel: &str) -> FileResult<()> {
        let parent = abs
            .parent()
            .ok_or_else(|| FileError::new(code::OUTSIDE_ROOT, format!("{rel:?} has no parent")))?;
        let canon = parent
            .canonicalize()
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("parent of {rel:?}: {e}")))?;
        Self::ensure_within(&self.canonical, &canon, rel)
    }
}

/// `.part` name: unique per stream id + a nonce so a predictable name cannot be
/// pre-planted (G14/G21). Entropy note: this uses process id + wall clock +
/// stream id, not a stack address (V2 §13 flagged the stack-address seed as an
/// unjustified entropy claim).
///
/// 竞争窗口是**声明过的**（评审 F5）：`create_new(true)` = `O_CREAT|O_EXCL`，
/// 在 Linux/POSIX 上对已存在的符号链接同样返回 `EEXIST` 而不跟随它，所以
/// "预置一个 `.part` 符号链接"这条攻击面是被拒的，不是靠 `O_NOFOLLOW`；
/// 但"父目录被换成链接"这一类 TOCTOU 仍然只能靠 `reverify_parent` 的事前/事后
/// 两次检查夹住，std 下没有第三道闸。这条残余风险写在 G13 与 `PRODUCT.md` §18.3
/// 的平台矩阵里，不假装它不存在。
fn part_path(target: &Path, stream: u64) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(target.as_os_str().as_encoded_bytes());
    h.update(stream.to_be_bytes());
    h.update((nanos as u64).to_be_bytes());
    h.update(std::process::id().to_le_bytes());
    let d = h.finalize();
    let mut tag = String::from("nexus-part-");
    for b in &d[..8] {
        tag.push_str(&format!("{b:02x}"));
    }
    let file_name = target
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let mut p = match target.parent() {
        Some(dir) => dir.to_path_buf(),
        None => PathBuf::from("."),
    };
    p.push(format!(".{file_name}.{tag}"));
    p
}

/// Constant-time byte comparison (no early exit on mismatch).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// Read until EOF or `buf.len()`, returning the number of bytes filled. Never
/// panics on a short file.
fn read_exact_or_partial(f: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nexus-file-engine-{name}-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn engine(dir: &Path) -> FileEngine {
        let root = SandboxRoot::open("downloads", dir, false).unwrap();
        FileEngine::new(FileLimits::default(), vec![root], "s3cret").unwrap()
    }

    /// Recursive listing (no `walkdir` dependency: the crate is std-only).
    fn walkdir(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for e in rd.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        stack.push(path.clone());
                    }
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn limits_cross_constraints_fail_closed() {
        let baseline = FileLimits::default();
        let l = FileLimits {
            chunk_bytes: baseline.max_buffered_amount + 1,
            ..Default::default()
        };
        assert_eq!(l.validate().unwrap_err().code, code::CONFIG);
        let m = FileLimits {
            max_sessions: 16,
            max_inflight_bytes_per_session: 16 * 1024 * 1024,
            ..Default::default()
        };
        assert_eq!(m.validate().unwrap_err().code, code::CONFIG);
        let z = FileLimits {
            max_browser_sessions: baseline.max_sessions + 1,
            ..Default::default()
        };
        assert_eq!(z.validate().unwrap_err().code, code::CONFIG);
        assert!(FileLimits::default().validate().is_ok());
    }

    #[test]
    fn sftp_backend_refuses_mutation_and_unwired_io() {
        // G14 fail-closed（owner 2026-10-11 选定 (b)）：ssh2 0.9.6 表达不出
        // "不覆盖的改名"（libssh2 通告并钳在 SFTP v3，rename 的 flags 只在
        // version>=5 入包），所以 SFTP 根上的变更操作结构性不可用，而不是
        // "实现时要小心"。
        assert!(BackendKind::Local.allows_mutation());
        assert!(!BackendKind::Sftp.allows_mutation());

        let dir = tmp("sftp-refuse");
        let remote = SandboxRoot::open_sftp("remotedir", "/home/user/files", false).unwrap();
        let local = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(FileLimits::default(), vec![local, remote], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();

        for err in [
            e.open_upload(s, "remotedir", "a.bin", Some(1))
                .map(|_| ())
                .unwrap_err(),
            e.mkdir(s, "remotedir", "sub").unwrap_err(),
            e.remove(s, "remotedir", "a.bin", false).unwrap_err(),
            e.rename(s, "remotedir", "a.bin", "b.bin").unwrap_err(),
        ] {
            assert_eq!(err.code, code::UNSUPPORTED, "mutation on an SFTP root");
        }
        // M1 还没接 SFTP 传输：读面也必须显式拒绝，不能把远端路径当本地路径
        // 去 stat（那会给出误导性的 NOT_FOUND）。
        assert_eq!(
            e.list(s, "remotedir", ".", 0).unwrap_err().code,
            code::UNSUPPORTED
        );
        assert_eq!(
            e.read_page(s, "remotedir", "a.bin", 0, 8).unwrap_err().code,
            code::UNSUPPORTED
        );
        // 远端根的形状检查：相对路径与含 .. 的路径都拒。
        assert_eq!(
            SandboxRoot::open_sftp("r", "home/user", false)
                .unwrap_err()
                .code,
            code::CONFIG
        );
        assert_eq!(
            SandboxRoot::open_sftp("r", "/home/../etc", false)
                .unwrap_err()
                .code,
            code::NON_CANONICAL_ROOT
        );
        // 本地根不受影响。
        assert!(e.open_upload(s, "downloads", "ok.bin", Some(1)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_canonical_root_is_rejected() {
        let dir = tmp("root");
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        // 形态一：尾斜杠。这是真实配置里最常见的写法，canonicalize 会把它去掉。
        let trailing = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
        assert_eq!(
            SandboxRoot::open("r", Path::new(&trailing), false)
                .unwrap_err()
                .code,
            code::NON_CANONICAL_ROOT,
            "trailing separator must not be accepted as canonical: {trailing:?}"
        );
        // 形态二：路径里带 ..，且解析后仍指向同一个目录（这才是"看起来合法"的写法；
        // 从 /tmp 出发写 ../x 会直接落到 /，那是另一种失败，测不到这条守卫）。
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let dotted = sub.join("..").join("sub");
        assert_eq!(
            SandboxRoot::open("r", &dotted, false).unwrap_err().code,
            code::NON_CANONICAL_ROOT,
            "an embedded .. component must be refused even when it resolves inside: {dotted:?}"
        );
        // 反例守卫：规范形必须被接受（否则上面两条就成了"永远拒绝"）。
        assert!(SandboxRoot::open("r", &dir, false).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_component_is_refused_on_every_verb() {
        let dir = tmp("symlink");
        let outside = tmp("outside");
        std::fs::write(outside.join("secret.txt"), "SECRET").unwrap();
        let link = dir.join("escape");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("secret.txt"), &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(outside.join("secret.txt"), &link).unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        for verb in ["list", "read", "remove"] {
            let r = match verb {
                "list" => e.list(s, "downloads", "escape", 0).map(|_| ()),
                "read" => e.read_page(s, "downloads", "escape", 0, 8).map(|_| ()),
                _ => e.remove(s, "downloads", "escape", false).map(|_| ()),
            };
            assert_eq!(r.unwrap_err().code, code::SYMLINK_ESCAPE, "verb {verb}");
        }
        // 差分：一个"只 canonicalize 一次然后相信它"的实现会直接走到沙箱外面。
        // 这一步刻意绕开引擎（引擎已经拒绝了），用来证明上面的拒绝不是装饰。
        let naive = std::fs::canonicalize(e.roots["downloads"].path().join("escape")).unwrap();
        assert!(
            !naive.starts_with(e.roots["downloads"].path()),
            "naive single-canonicalize resolver was supposed to escape: {naive:?}"
        );
        assert!(std::fs::read(outside.join("secret.txt")).is_ok());
        e.close_session(s, "loopback").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn upload_acks_only_contiguous_bytes() {
        let dir = tmp("upload");
        std::fs::write(dir.join("seed.txt"), "seed").unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let payload: Vec<u8> = (0..24u8).collect();
        let id = e.open_upload(s, "downloads", "out.bin", Some(24)).unwrap();
        assert_eq!(e.stage_chunk(s, id, 0, &payload[..8]).unwrap(), 8);
        assert_eq!(e.ack_staged(s, id).unwrap(), 8);
        // duplicate page: accepted only because it matches byte-for-byte
        assert_eq!(e.stage_chunk(s, id, 0, &payload[..8]).unwrap(), 8);
        assert!(e.stage_chunk(s, id, 0, &[0u8; 8]).is_err());
        // partial overlap and jumps are refused; the prefix is never rewritten
        assert_eq!(
            e.stage_chunk(s, id, 4, &payload[4..16]).unwrap_err().code,
            code::INTEGRITY
        );
        assert_eq!(
            e.stage_chunk(s, id, 20, &payload[20..]).unwrap_err().code,
            code::INTEGRITY
        );
        assert_eq!(e.stage_chunk(s, id, 8, &payload[8..16]).unwrap(), 16);
        assert_eq!(e.stage_chunk(s, id, 16, &payload[16..]).unwrap(), 24);
        let name = e.commit_upload(s, "downloads", id, None).unwrap();
        assert_eq!(name, "out.bin");
        assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), payload);
        // no .part residue
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("nexus-part"))
            .collect();
        assert_eq!(leftovers.len(), 0);
        e.close_session(s, "loopback").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rehash_budget_covers_replay_not_digest_publishing() {
        // 评审 WARN：旧实现把 `max_rehash_bytes_per_stream` 当**验证门**用，
        // 于是大于该预算的工件永远拿不到摘要，无法带 `expected_sha256` 发布。
        // 现在预算只覆盖"重放页的磁盘回读"，顺序字节一直进摘要。
        let dir = tmp("rehash");
        let l = FileLimits {
            chunk_bytes: 8,
            max_rehash_bytes_per_stream: 16,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let payload: Vec<u8> = (0..48u8).collect(); // 48 > 16 的 rehash 预算
        let want: [u8; 32] = Sha256::digest(&payload).into();
        let id = e.open_upload(s, "downloads", "big.bin", Some(48)).unwrap();
        for (i, chunk) in payload.chunks(8).enumerate() {
            e.stage_chunk(s, id, (i * 8) as u64, chunk).unwrap();
        }
        assert_eq!(e.ack_staged(s, id).unwrap(), 48);
        // 顺序上传全程在预算之外，摘要仍然完整可用：发布必须成功。
        let name = e.commit_upload(s, "downloads", id, Some(want)).unwrap();
        assert_eq!(name, "big.bin");
        assert_eq!(std::fs::read(dir.join("big.bin")).unwrap(), payload);

        // 重放侧：同一页反复回读，超过预算就显式拒绝，不是静默少算。
        let id2 = e.open_upload(s, "downloads", "b2.bin", Some(8)).unwrap();
        e.stage_chunk(s, id2, 0, &payload[..8]).unwrap();
        for _ in 0..2 {
            e.stage_chunk(s, id2, 0, &payload[..8]).unwrap(); // 8 + 8 = 16 == 预算
        }
        let err = e.stage_chunk(s, id2, 0, &payload[..8]).unwrap_err();
        assert_eq!(err.code, code::CAPACITY, "回读预算必须封顶重放成本: {err}");
        e.abort_upload(s, id2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_never_overwrites_an_existing_target() {
        let dir = tmp("noreplace");
        std::fs::write(dir.join("target.bin"), "ORIGINAL").unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        // Opening onto an existing target is already refused, and the original
        // bytes must be untouched.
        assert_eq!(
            e.open_upload(s, "downloads", "target.bin", Some(4))
                .unwrap_err()
                .code,
            code::EXISTS
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("target.bin")).unwrap(),
            "ORIGINAL"
        );
        // And if a target appears between open and commit, hard_link refuses.
        let id = e.open_upload(s, "downloads", "late.bin", Some(4)).unwrap();
        e.stage_chunk(s, id, 0, b"NEWW").unwrap();
        std::fs::write(dir.join("late.bin"), "RACE").unwrap();
        assert_eq!(
            e.commit_upload(s, "downloads", id, None).unwrap_err().code,
            code::EXISTS
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("late.bin")).unwrap(),
            "RACE"
        );
        // 被拒绝的发布不留 `.part`（G14）。这条断言是 E4 场景实测抓到残留之后补的：
        // 缺了它单测照样全绿，而每个 OUTPUT_EXISTS 拒绝都会在节点上留一份无人负责的
        // 中转字节（V1 的清扫依赖 root 打开时机，属于另一种补救，不算这里做对了）。
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|d| d.file_name().to_string_lossy().contains("nexus-part"))
            .collect();
        assert_eq!(
            leftovers.len(),
            0,
            "refused publish must not leave .part behind"
        );
        e.close_session(s, "loopback").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lockout_refuses_even_the_correct_token_and_stays_bounded() {
        let dir = tmp("throttle");
        let mut e = engine(&dir);
        let after = e.limits().lockout_after;
        for i in 0..after {
            let err = e.authenticate("attacker", "10.0.0.1", "wrong").unwrap_err();
            assert_eq!(
                err.code,
                if i + 1 == after {
                    code::THROTTLED
                } else {
                    code::AUTH_DENIED
                }
            );
        }
        assert_eq!(
            e.authenticate("attacker", "10.0.0.1", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED
        );
        // a different source is not locked by the attacker's bucket
        assert!(e.authenticate("attacker", "10.0.0.2", "s3cret").is_ok());
        // forged volume must not grow the table linearly.
        // 地址必须轮换：全灌在一个地址上时，本批新加的单源额度会让表只长到 40 行，
        // 那句 `<= max_throttle_buckets` 就变成"永远离上界很远"的空断言（r9 R9-N-1）。
        // 顺带断言表**确实被灌满**，这条才有上下两侧。
        for i in 0..(e.limits().max_throttle_buckets * 3) {
            let forged = format!("p{i}");
            let slot = i / 32;
            let addr = format!("10.7.{}.{}", slot / 256, slot % 256);
            let _ = e.authenticate(&forged, &addr, "wrong");
        }
        assert_eq!(e.throttle_buckets(), e.limits().max_throttle_buckets);
        assert!(e.throttle_overflow() > 0, "表满之后必须走溢出计数这条路");
        assert!(e.throttle_globally_locked());
        assert!(e.throttle_buckets() <= e.limits().max_throttle_buckets);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminal_class_has_priority_over_file_class() {
        let mut b = SendBudget::new(100);
        for _ in 0..10 {
            b.push_file(1, 10).unwrap();
        }
        assert_eq!(b.push_file(1, 10).unwrap_err().code, code::QUEUE_FULL);
        assert_eq!(b.file_drops, 1);
        assert_eq!(b.pending_file_messages(), 10);
        assert_eq!(b.file_buffered_for(1), 100);
        // 一条 50 字节的 terminal 消息要挤掉 **5 条** file 消息，账上必须记 5，
        // 不是"发生过一次挤占"（评审 r1 F2：旧实现 `usize::from(freed > 0)` 恒为 1）。
        // 挤掉的**是谁的消息**也必须报出来，否则会话侧的 in-flight 永远冲不回去
        // （评审 r2 NEW-2 第 1 点）。
        let (evicted, ok) = b.push_terminal(50);
        assert!(ok.is_ok());
        assert_eq!(evicted.len(), 5, "返回值就是被挤掉的消息清单");
        assert!(evicted.iter().all(|(s, n)| *s == 1 && *n == 10));
        assert_eq!(b.terminal_accepted, 1);
        assert_eq!(b.terminal_drops, 0);
        assert_eq!(b.file_drops, 6, "1 条被拒 + 5 条被挤掉");
        assert_eq!(b.pending_file_messages(), 5);
        assert_eq!(b.file_buffered_for(1), 50);
        assert_eq!(b.buffered(), 100);
        b.settle_terminal(50);
        // 严格 FIFO：队头不是这个会话的，就不许越过它去释放后面的
        // （评审 r3 R3-W-4：旧实现扫全队列，等于给还在缓冲里的字节提前退额度）。
        assert_eq!(b.settle_file(2, 50), 0);
        b.push_file(2, 20).unwrap();
        assert_eq!(
            b.settle_file(2, 20),
            0,
            "队头是会话 1 的消息，会话 2 不得插队释放"
        );
        assert_eq!(b.file_buffered_for(2), 20);
        assert_eq!(b.settle_file(1, 10), 10);
        assert_eq!(b.settle_file(1, 4), 0, "部分 settle 不得虚报：整条才能出队");
        // 会话 2 的消息排在会话 1 的**四条**之后，只能等它们全部落地。
        assert_eq!(b.settle_file(2, 20), 0, "队头仍是会话 1，会话 2 不得插队");
        assert_eq!(
            b.settle_file(1, 40),
            40,
            "一次 settle 可以连续冲多条本会话消息"
        );
        assert_eq!(b.settle_file(2, 20), 20, "队头轮到会话 2 后才释放");
        assert_eq!(b.file_buffered_for(1), 0);
        assert_eq!(b.pending_file_messages(), 0);
        // 会话消失：它占着的全部条目一次释放（close/sweep 走的就是这条）。
        b.push_file(9, 12).unwrap();
        b.push_file(9, 8).unwrap();
        b.push_file(7, 5).unwrap();
        assert_eq!(b.release_session(9), 20);
        assert_eq!(b.file_buffered_for(7), 5, "别的会话不得被连带释放");
        b.settle_terminal(50);
        assert_eq!(b.terminal_buffered, 0);
    }

    #[test]
    fn failed_terminal_send_still_hands_back_the_evicted_list() {
        // 评审 r3 R3-NEW-1：旧签名 `FileResult<Vec<..>>` 在失败分支把清单随 Err
        // 一起丢掉，而挤占**已经发生**并计入 file_drops ⇒ 那些会话的 in-flight
        // 额度永久悬空，G16 自己的不变量 `inflight == budget.file_buffered_for`
        // 反向背离且没有释放 API。
        let mut d = SendBudget::new(100);
        let (ev0, ok0) = d.push_terminal(80);
        assert!(ok0.is_ok() && ev0.is_empty());
        d.push_file(1, 15).unwrap();
        let (ev1, res1) = d.push_terminal(30);
        assert!(
            res1.is_err(),
            "终端字节占位时腾不出空间必须硬失败，不得静默挤"
        );
        assert_eq!(ev1, vec![(1, 15)], "失败路径也必须交回被挤掉的消息");
        assert_eq!(d.file_drops, 1);
        assert_eq!(d.file_buffered_for(1), 0);

        // 一条比整个预算还大的消息：一条文件消息都不该挤。
        let mut e = SendBudget::new(100);
        e.push_file(1, 10).unwrap();
        let (ev, res) = e.push_terminal(200);
        assert!(res.is_err());
        assert!(ev.is_empty(), "不可能发出去的终端消息不得白赔文件字节");
        assert_eq!(e.file_drops, 0);
        assert_eq!(e.pending_file_messages(), 1);

        // 引擎侧：失败发送之后额度必须已回冲（inflight_matches_budget 是引擎自证）。
        // 夹具要满足 G12：ack 下限 124 ≤ 预算，所以预算取 128。
        let dir = tmp("terminal-fail");
        let l = FileLimits {
            chunk_bytes: 32,
            max_inflight_bytes_per_session: 128,
            max_ack_bytes: 128,
            max_buffered_amount: 128,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut eng = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = eng.authenticate("u", "loopback", "s3cret").unwrap();
        eng.send_terminal(96).unwrap();
        eng.send_file_message(s, 16).unwrap();
        assert_eq!(eng.inflight_bytes(s), 16);
        assert!(
            eng.send_terminal(96).is_err(),
            "终端字节占位 + 已无文件消息可挤 ⇒ 必须硬失败，不得静默挤"
        );
        assert_eq!(eng.budget().file_drops, 1, "被挤掉的那条要计入");
        assert_eq!(
            eng.inflight_bytes(s),
            0,
            "被挤掉的 16 字节必须已回冲会话额度"
        );
        assert!(eng.inflight_matches_budget(s));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lockout_rearms_after_expiry_and_flood_arms_are_not_exempt() {
        // 评审 r3 R3-NEW-2 / R3-W-2：
        //  (a) 全局窗口旧写法只作用于"不在 buckets 里"的主体 ⇒ 把表填满的那批
        //      principal 恰好被豁免，反而永久绕开锁定点；
        //  (b) `locked` 的到期项从不回收 ⇒ 灌满之后 record_failure 只能设全局窗口，
        //      叠加 (a) 就是"已在册主体永远锁不住"；
        //  (c) 溢出计数只增不减 ⇒ 一次洪水之后每窗口一条伪造失败就能无限续期。
        // 窗口取 300 ms 而不是更小的值：本测试要跨四个阶段，衰减判据是"距上一次
        // 失败满一个窗口"，窗口越小越容易被 CI 抖动假红（一次 >40 ms 的停顿就能让
        // 后半段的溢出分支变成单桶分支）。
        let dir = tmp("throttle-rearm");
        let window = Duration::from_millis(300);
        let l = FileLimits {
            max_throttle_buckets: 8,
            lockout_after: 2,
            // 额度取交叉规则允许的上界 8×2，好让下面的单源洪水（12 条）仍然走
            // 两层键的溢出分支，而不是先撞上源锁。
            max_failures_per_source: 16,
            lockout_window: window,
            max_sessions: 8,
            max_browser_sessions: 8,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();

        // 同一 principal：锁定 → 正确口令被拒 → 窗口过期 → 再失败 → **必须重新锁上**
        for _ in 0..e.limits().lockout_after {
            let _ = e.authenticate("repeat", "10.0.0.1", "wrong");
        }
        assert_eq!(
            e.authenticate("repeat", "10.0.0.1", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED
        );
        std::thread::sleep(window * 2);
        for _ in 0..e.limits().lockout_after {
            let _ = e.authenticate("repeat", "10.0.0.1", "wrong");
        }
        assert_eq!(
            e.authenticate("repeat", "10.0.0.1", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "锁到期后再次失败必须能重新上锁，而不是永久放行"
        );

        // 填满表并让全局窗口生效，然后等它过期：溢出计数必须归零，
        // 不能靠"每窗口一条失败"无限续期。
        for i in 0..(e.limits().max_throttle_buckets + 4) {
            let _ = e.authenticate(&format!("flood{i}"), "10.0.0.2", "wrong");
        }
        assert!(e.throttle_globally_locked(), "溢出必须升级为全局窗口");
        // 评审 r4 R4-W-1：**必须断言一个已在册的主体**。上一版这里断言的是
        // `in-table-but-not-locked`（其实根本不在 buckets 里），于是把豁免逻辑
        // 换回去也照样绿——这条才是真正的杀伤性判据：旧写法额外要求"不在 buckets
        // 里"才受全局窗口约束，所以把表填满的那批 principal 恰好被豁免，永久锁不住。
        assert_eq!(
            e.throttle_buckets(),
            e.limits().max_throttle_buckets,
            "夹具前提：表已满，flood0 在册且自身没有被锁"
        );
        assert_eq!(
            e.authenticate("flood0", "10.0.0.2", "s3cret")
                .map(|_| "ACCEPTED")
                .unwrap_or_else(|err| err.code),
            code::THROTTLED,
            "已在册主体在全局窗口内同样必须被拒（旧豁免逻辑下这里是 ACCEPTED）"
        );
        // 同一窗口内不在册的主体也必须被拒（fail-closed 覆盖面完整）。
        assert_eq!(
            e.authenticate("not-in-table", "10.0.0.2", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED
        );
        std::thread::sleep(window * 2);
        assert!(
            !e.throttle_globally_locked(),
            "窗口必须自行过期，不靠持续注入伪造失败"
        );
        assert!(
            e.authenticate("late-comer", "10.0.0.3", "s3cret").is_ok(),
            "窗口过期后合法用户必须能进来（fail-closed 不等于永久拒绝服务）"
        );

        // R4-W-6（owner 裁决：实现**桶衰减**，而不是把"合法用户可被长期拒服务"
        // 写成可接受代价）。洪水停止满一个窗口之后，占位的伪造桶必须自己消失：
        // 新来的合法主体重新拿到**自己的桶**，而不是被扫进 fail-closed 的溢出人群。
        // 删掉 `decay` 里的桶回收，这里就会红（旧语义下表还被 8 个死桶占着，
        // post-flood 进溢出分支 ⇒ `throttle_overflow() == 1`）。
        assert_eq!(
            e.throttle_overflow(),
            0,
            "停止注入一个窗口后溢出计数必须归零"
        );
        assert_eq!(e.throttle_failures(), 0, "桶计数同样必须随窗口清干净");
        let _ = e.authenticate("post-flood", "10.0.0.3", "wrong");
        assert_eq!(
            e.throttle_overflow(),
            0,
            "表已自愈 ⇒ 这条失败落进它自己的桶，不再进溢出人群"
        );
        assert_eq!(e.throttle_buckets(), 1);
        assert_eq!(e.throttle_failures(), 1);

        // 重新武装必须靠**持续注入**：先把表重新填满，再攒满 `lockout_after` 条
        // 溢出失败。评审 r5 R5-NEW-1 的杀伤性保留：若 `global` 不随窗口归零，旧值
        // （5）还挂着，下面第一条溢出失败就会立刻武装 ⇒ "不得武装"这条变红。
        let free = e.limits().max_throttle_buckets - e.throttle_buckets();
        for i in 0..free {
            let _ = e.authenticate(&format!("again{i}"), "10.0.0.4", "wrong");
        }
        assert_eq!(e.throttle_buckets(), e.limits().max_throttle_buckets);
        assert_eq!(e.throttle_overflow(), 0, "填满但未超阈值时不得武装");
        for n in 1..e.limits().lockout_after {
            let _ = e.authenticate(&format!("drip{n}"), "10.0.0.4", "wrong");
            assert!(
                !e.throttle_globally_locked(),
                "攒够 lockout_after 条溢出失败之前不得武装"
            );
        }
        let _ = e.authenticate("drip-final", "10.0.0.4", "wrong");
        assert!(
            e.throttle_globally_locked(),
            "攒满 lockout_after 条溢出失败后必须重新武装全局窗口"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lockout_requires_failures_inside_one_window() {
        // 桶衰减换来的**另一侧**口径，必须写死在测试里而不是只写在契约里：
        // `lockout_after` 条失败必须发生在同一个窗口内才会武装，所以"每窗口一条"
        // 的慢滴不再锁死一个身份（R4-W-6 的取舍：锁定门槛从"累计 5 条"变成
        // "一个窗口内 5 条"）。衰减只有 `decay` 一个机制：把它的桶回收改掉（变异 M1），
        // 跨窗口的失败就一路累加到阈值，第三轮第一条直接锁定 ⇒ 这条立刻红。
        let dir = tmp("throttle-drip");
        let window = Duration::from_millis(200);
        let l = FileLimits {
            lockout_after: 3,
            lockout_window: window,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        for round in 0..3 {
            let err = e
                .authenticate("drip", "10.0.0.7", "wrong")
                .unwrap_err()
                .code;
            assert_eq!(
                err,
                code::AUTH_DENIED,
                "第 {round} 轮：跨窗口的失败不得累计"
            );
            std::thread::sleep(window + window / 2);
        }
        // 反过来：一个窗口内攒满 3 条**必须**锁定，否则衰减就成了免死金牌。
        for _ in 0..2 {
            let _ = e.authenticate("drip", "10.0.0.7", "wrong");
        }
        assert_eq!(
            e.authenticate("drip", "10.0.0.7", "wrong")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "同一窗口内达到阈值必须锁定"
        );
        assert_eq!(
            e.authenticate("drip", "10.0.0.7", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn throttle_identity_keys_do_not_collide_on_prefix_or_concatenation() {
        // 评审 r6 NOTE-4（owner 裁决：节流键改成身份摘要）。旧写法把两半各自裁到
        // 固定长度（128 B），所以碰撞条件是"前 128 字节相同 **且总长相同**"——夹具
        // 必须同时满足这两条，否则测的是字符串不等而不是摘要。
        let mut t = Throttle::new(16, 3, Duration::from_secs(60), 12);
        let base = "b".repeat(200);
        let victim = format!("{base}aaaa");
        let forged = [
            format!("{base}bbbb"),
            format!("{base}cccc"),
            format!("{base}dddd"),
        ];
        for f in &forged {
            for _ in 0..t.lockout_after {
                let _ = t.record_failure(f, "10.0.0.8");
            }
            assert!(t.is_locked(f, "10.0.0.8"), "{f} 自己必须被锁");
            assert!(
                !t.is_locked(&victim, "10.0.0.8"),
                "同前缀同总长的伪造身份不得替受害者武装锁定（裁剪键下这里是 true）"
            );
        }
        // 受害者随后自己也错一次：只能推进自己的桶，不得继承伪造者的计数。
        // 裁剪键下这一条会把共用桶推到 10 并立刻重新武装 ⇒ 返回 true ⇒ 红。
        assert!(
            !t.record_failure(&victim, "10.0.0.8"),
            "受害者自己的第一条失败不得复用伪造者的计数"
        );
        assert_eq!(t.buckets(), forged.len() + 1, "四条身份必须各自成桶");
        assert_eq!(t.failure_count(), 3 * t.lockout_after + 1);
        // 长度前缀缺了就会碰撞的拼接面：("ab","c") 与 ("a","bc") 是同一段拼接。
        let mut u = Throttle::new(16, 2, Duration::from_secs(60), 8);
        for _ in 0..u.lockout_after {
            let _ = u.record_failure("ab", "c");
        }
        assert!(u.is_locked("ab", "c"));
        assert!(
            !u.is_locked("a", "bc"),
            "两半必须先写长度再哈希，否则拼接歧义给出免费碰撞"
        );
        // 这一条只是回归护栏：不写长度前缀时 `("ab","bc")` 也不会与上面两段同键，
        // 真正有杀伤力的是上面那一对。
        assert!(!u.is_locked("ab", "bc"), "源地址同样不得被并进同一条键");
        // 定长摘要 ⇒ "项数有界"就是"字节有界"，不依赖任何裁剪（R5-W-4 的原始诉求）。
        assert_eq!(u.buckets(), 1, "只有实际被喂过的那条身份在册");
        assert_eq!(u.failure_count(), u.lockout_after);
    }

    #[test]
    fn expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window() {
        // 过期的 `locked` 项必须真的被回收，而不是只靠时间戳比较"看起来没锁"。
        // 两种写法在判定上等价，但内存与**升级路径**不等价：`record_failure` 只在
        // `locked.len() >= max_buckets` 时才升级到全局窗口，所以死锁项占位会把后来者
        // 的**个体锁定**偷偷换成**全局 fail-closed**——一批早就停手的伪造身份，
        // 从此永久决定所有新身份的待遇。变异 M9（把 `locked.retain` 改成恒真）
        // 在第一版这里全绿，所以两条断言都写上：全局窗口不得武装，且过期身份的
        // 正确令牌必须重新能进来。
        let dir = tmp("lock-reclaim");
        let window = Duration::from_millis(200);
        let l = FileLimits {
            max_throttle_buckets: 2,
            lockout_after: 2,
            // 小表必须带一个小源额度（G12 的交叉规则：`max_failures_per_source` 不得
            // 超过 `max_throttle_buckets × lockout_after`，否则它永远轮不到开火）。
            // 也正因为额度只有 4，下面两条身份各用**自己的**源地址：共用一个地址的话，
            // 第 4 条失败会先武装源锁，测试就变成在测源额度而不是个体锁定。
            max_failures_per_source: 4,
            lockout_window: window,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        for (who, addr) in [("first", "10.0.0.20"), ("second", "10.0.0.22")] {
            for _ in 0..e.limits().lockout_after {
                let _ = e.authenticate(who, addr, "wrong");
            }
            assert_eq!(
                e.authenticate(who, addr, "s3cret").unwrap_err().code,
                code::THROTTLED
            );
        }
        assert!(
            !e.throttle_globally_locked(),
            "夹具前提：两条身份各自占满一个锁位，还没有升级"
        );
        std::thread::sleep(window * 2);
        // 第三条身份到阈值：死锁项若不被回收，锁表在这里就"满了"，悄悄升级为全局窗口。
        for _ in 0..e.limits().lockout_after {
            let _ = e.authenticate("third", "10.0.0.21", "wrong");
        }
        assert!(
            !e.throttle_globally_locked(),
            "过期锁必须回收；升级为全局窗口是把个体锁定偷换成全体拒服务（M9）"
        );
        assert_eq!(
            e.authenticate("third", "10.0.0.21", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "第三条身份自己的锁要成立"
        );
        assert!(
            e.authenticate("first", "10.0.0.20", "s3cret").is_ok(),
            "已过期身份不得被死锁项继续拦在门外"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_teardown_touches_no_throttle_state() {
        // 评审 r7 R7-W-2 → r8 R8-W-2 两轮修正的落点：**会话拆除不碰节流状态的任何一个
        // 部分**（既不删锁，也不删计数），完整因果写在 `Throttle::succeed` 的三段历史
        // 注释里。要点复述一遍，因为"为什么连清计数都不许"并不显然：
        // 锁是由**计数**达到 `lockout_after` 才武装的，而 `close_session` 在 M2 接线前
        // 没有归属检查、会话号顺序自增 ⇒ 只要拆会话还能清计数，一个能猜整数的第三方
        // 每 `lockout_after - 1` 次替受害者关一次会话，就能把计数按定义钉在阈值之下，
        // 锁**永远武装不了**——这比"拆会话即解锁"还省事。
        // 两半都没有时间依赖。旧写法（第八片：清计数；更早：连锁一起清）在这里都红。
        let dir = tmp("teardown-throttle");
        let l = FileLimits {
            lockout_after: 2,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();

        // (a) 计数不被清：成功认证 → 1 条失败（未武装）→ 关会话 → 再 1 条失败
        //     ⇒ 计数仍在 ⇒ 第二条达到阈值 ⇒ 当场武装。
        let sid = e
            .authenticate("td-count", "10.0.0.30", "s3cret")
            .unwrap_or_else(|_| panic!("夹具：正确令牌应放行"));
        assert_eq!(
            e.authenticate("td-count", "10.0.0.30", "wrong")
                .unwrap_err()
                .code,
            code::AUTH_DENIED,
            "夹具前提：第一条失败不该武装"
        );
        e.close_session(sid, "10.0.0.30").unwrap();
        assert_eq!(
            e.authenticate("td-count", "10.0.0.30", "wrong")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "拆会话不得清计数：清了就等于让第三方把该身份的计数永远压在阈值下（r8 R8-W-2）"
        );

        // (b) 锁不被拆：持有会话 → 失败到武装 → 关会话 → 正确令牌仍必须被拒。
        let sid2 = e.authenticate("td-lock", "10.0.0.31", "s3cret").unwrap();
        for _ in 0..e.limits().lockout_after {
            let _ = e.authenticate("td-lock", "10.0.0.31", "wrong");
        }
        assert_eq!(
            e.authenticate("td-lock", "10.0.0.31", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "夹具前提：已达阈值并武装"
        );
        e.close_session(sid2, "10.0.0.31").unwrap();
        // 不变式见证（r8 R8-W-3：这条之前锁表大小全仓不可读，"表项有界"对锁表那一半
        // 是零可红对象）：每条活锁都得有一行活着，行与计数都不许被拆除动过。
        assert_eq!(
            e.throttle_locks(),
            e.throttle_buckets(),
            "`locked.len() == buckets.len()`：孤锁没有来源，所以那支纵深防御经 authenticate 到不了"
        );
        assert!(
            e.throttle_locks() <= e.limits().max_throttle_buckets,
            "锁表同样有界（G15 标题那句现在两边都有观测面）"
        );
        assert_eq!(
            e.throttle_failures(),
            2 * e.limits().lockout_after,
            "两次拆会话都没动过计数：td-count 与 td-lock 各自 2 条仍在册"
        );
        assert!(
            e.throttle_locked("td-lock", "10.0.0.31"),
            "锁还在——拆会话不是解锁路径"
        );
        let after_teardown = e
            .authenticate("td-lock", "10.0.0.31", "s3cret")
            .map(|_| "ACCEPTED")
            .unwrap_or_else(|err| err.code);
        assert_eq!(
            after_teardown,
            code::THROTTLED,
            "拆除会话不是解锁路径：窗口必须服完（旧 forget 这里是 ACCEPTED）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_recycle_clears_no_throttle_state() {
        // 另一半柱子（`Throttle::succeed` 的历史三段）：显式 `close_session` 与闲置回收
        // `sweep_idle` **都**不碰节流状态。上一条测试管 close 那一侧，本条管回收那一侧：
        // 若 sweep_idle 去清计数，下面第二条失败就只是 AUTH_DENIED ⇒ 红；若它清锁，
        // 同一夹具里 `throttle_locked` 变 false ⇒ 也红。
        let dir = tmp("idle-throttle");
        let l = FileLimits {
            idle_timeout: Duration::from_millis(20),
            lockout_after: 2,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("idle-td", "10.0.0.32", "s3cret").unwrap();
        assert_eq!(
            e.authenticate("idle-td", "10.0.0.32", "wrong")
                .unwrap_err()
                .code,
            code::AUTH_DENIED
        );
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            e.sweep_idle(Instant::now()),
            vec![s],
            "夹具前提：会话确实被闲置回收"
        );
        assert_eq!(
            e.authenticate("idle-td", "10.0.0.32", "wrong")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "闲置回收不得清掉失败计数，否则'把会话挂到超时'就是免费的清账路径"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn closing_another_peers_session_is_refused_and_leaves_it_intact() {
        // r8 R8-W-2 的根因就在这一半：在归属检查之前，`close_session(id)` 对任意调用方
        // 都会删会话、删**别人的** `.part` 暂存文件并释放其预算，而会话号顺序自增、
        // 可枚举。现在必须出示与会话相同的传输地址；且拒绝时不区分"这个 id 不存在"
        // 与"这个 id 存在但不属于你"，否则这条入口自己就成了会话枚举的 oracle。
        let dir = tmp("close-owner");
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(FileLimits::default(), vec![root], "s3cret").unwrap();
        let victim = e
            .authenticate("victim", "10.0.0.40", "s3cret")
            .expect("fixture: correct token admits");
        let _st = e.open_upload(victim, "downloads", "u.bin", None).unwrap();
        e.stage_chunk(victim, _st, 0, b"abc").unwrap();
        let parts = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|d| d.file_name().to_string_lossy().contains("nexus-part"))
                .count()
        };
        assert_eq!(parts(), 1, "夹具前提：暂存文件在场");
        let before_audit = e.audit().len();
        assert_eq!(
            e.close_session(victim, "10.0.0.41")
                .map(|_| "OK")
                .unwrap_err()
                .code,
            code::NOT_FOUND,
            "地址不符必须拒，且不得泄露这个 id 是否存在"
        );
        assert_eq!(
            e.audit().len(),
            before_audit + 1,
            "拒绝也要恰好留一行（G21）"
        );
        assert_eq!(
            parts(),
            1,
            "被拒的拆除不得删掉别人的暂存文件（这才是真正的 DoS 面）"
        );
        assert!(
            e.stat(victim, "downloads", ".").is_ok(),
            "会话必须还活着：没被终止、预算没被释放"
        );
        // 不存在的 id 与不属于自己的 id：审计行的动作、码、principal 格必须逐字相同。
        let _ = e.close_session(999_999, "10.0.0.41");
        let rec_unknown = e.audit().back().unwrap().clone();
        let _ = e.close_session(victim, "10.0.0.41");
        let rec_foreign = e.audit().back().unwrap().clone();
        assert_eq!(rec_unknown.result_code, rec_foreign.result_code);
        assert_eq!(rec_unknown.action, rec_foreign.action);
        assert_eq!(
            rec_unknown.principal, rec_foreign.principal,
            "泄露归属的那一格也必须相同"
        );
        e.close_session(victim, "10.0.0.40")
            .expect("owner closes its own session");
        assert_eq!(parts(), 0, "只有所有者关闭时才清暂存文件");
        assert_eq!(
            e.stat(victim, "downloads", ".")
                .map(|_| "OK")
                .unwrap_err()
                .code,
            code::NOT_FOUND,
            "关闭之后会话确实没了"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_source_budget_locks_the_address_not_the_whole_node() {
        // 评审 r7 整改清单第 3 条 / r8 R7-N-9：键是 (主体,源) 的**对**，所以一个地址
        // 本来可以替任意多个自己并不拥有的主体，把整张表的额度池花光。这条限额锁的是
        // 这个地址本身，并且**不**升级为全体拒服务（后者是溢出计数那条大路的效果）。
        let dir = tmp("source-budget");
        let l = FileLimits {
            lockout_after: 3,
            max_failures_per_source: 6,
            max_throttle_buckets: 64,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        // 同一地址、六个不同主体：每个都没到自己的阈值（3），但源额度正好在第 6 条花完。
        for i in 0..6 {
            let seen = e
                .authenticate(&format!("p{i}"), "10.0.0.50", "wrong")
                .map(|_| "NONE")
                .unwrap_err()
                .code;
            assert_eq!(
                seen,
                if i == 5 {
                    code::THROTTLED
                } else {
                    code::AUTH_DENIED
                },
                "第 {} 条：只有把额度花完的那一条才报锁定",
                i + 1
            );
        }
        assert_eq!(e.throttle_source_locks(), 1, "源锁必须真的武装了一道");
        assert!(
            !e.throttle_globally_locked(),
            "单源超限不得升级为全体 fail-closed"
        );
        assert_eq!(
            e.authenticate("fresh", "10.0.0.50", "s3cret")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "同一地址的**新**主体也在门外：锁的是地址，不是那个主体"
        );
        assert!(
            e.authenticate("fresh", "10.0.0.51", "s3cret").is_ok(),
            "别的地址不受牵连——爆炸半径就到这台地址为止"
        );
        assert!(
            e.throttle_buckets() < e.limits().max_throttle_buckets,
            "夹具前提：离表满还远，所以这条限额不是溢出分支的替身"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_address_is_locked_when_the_source_ledger_is_full() {
        // 源账本与两层键同一条原则：**不**为陌生地址无限建行，而是当场锁它
        // （fail-closed）。这一条测的就是那个满表分支——把它改成"直接放过"
        // （变异 P3）时，内存上界仍然成立，但一个用大量源地址低速率撒失败的攻击者
        // 就可以让每个新地址都免费贡献失败，限额形同不存在。
        let dir = tmp("source-ledger-full");
        let l = FileLimits {
            max_throttle_buckets: 2,
            // 阈值抬高，确保下面没有任何一条失败撞上**个体**阈值，锁只可能来自源侧。
            lockout_after: 9,
            max_failures_per_source: 12,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        for i in 0..2 {
            assert_eq!(
                e.authenticate(&format!("known{i}"), &format!("10.0.0.6{i}"), "wrong")
                    .unwrap_err()
                    .code,
                code::AUTH_DENIED,
                "夹具前提：两个在册地址各花 1 条，账本刚好占满"
            );
        }
        assert_eq!(e.throttle_source_ledgers(), 2);
        assert_eq!(
            e.authenticate("arrives-late", "10.0.0.63", "wrong")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "账本满时陌生地址必须当场被锁，而不是免费记一条失败"
        );
        assert_eq!(e.throttle_source_locks(), 1);
        assert_eq!(
            e.throttle_source_ledgers(),
            2,
            "被锁的地址不占账本位（否则满表分支会自己把表撑大）"
        );
        assert!(
            !e.throttle_globally_locked(),
            "锁一个地址不等于锁全节点——这条与溢出计数那条大路必须可区分"
        );
        assert_eq!(
            e.authenticate("arrives-late", "10.0.0.63", "s3cret")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "正确口令也走不出源锁（与个体锁同一条口径）"
        );
        assert!(
            e.authenticate("known0", "10.0.0.60", "s3cret").is_ok(),
            "已在册地址不受牵连"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_lock_table_full_escalates_instead_of_growing_forever() {
        // r9 R9-W-2 抓到的那条路：源锁表原先没有插入门禁，而"账本满 ⇒ 陌生地址
        // 第一条失败就锁"恰恰是**最便宜**的填表方式（1 次请求换 1 条表项）。
        // 现在锁表满了必须与两层键同形：升级为全局窗口。删掉那道门禁（把
        // `arm_source` 里的 `>= max_buckets` 改成恒假）这条就红——它不会拒绝注入，
        // 只会让表无界地长下去，所以断言的是"到点了必须换成全局 fail-closed"。
        let dir = tmp("source-locks-full");
        let l = FileLimits {
            max_throttle_buckets: 2,
            lockout_after: 9,
            max_failures_per_source: 12,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        // 账本先灌满（2 个地址），之后每个新地址的第一条失败都会去插一道源锁。
        for i in 0..2 {
            let _ = e.authenticate(&format!("ledger{i}"), &format!("10.0.8.{i}"), "wrong");
        }
        assert_eq!(e.throttle_source_ledgers(), 2);
        for i in 0..2 {
            assert_eq!(
                e.authenticate(&format!("fresh{i}"), &format!("10.0.9.{i}"), "wrong")
                    .map(|_| "NONE")
                    .unwrap_err()
                    .code,
                code::THROTTLED,
                "账本满时陌生地址第一条就被锁"
            );
        }
        assert_eq!(e.throttle_source_locks(), 2, "夹具前提：锁表也满了");
        assert!(
            !e.throttle_globally_locked(),
            "满的那一刻还不该升级，升级属于下一条"
        );
        let _ = e.authenticate("one-too-many", "10.0.9.9", "wrong");
        assert!(
            e.throttle_globally_locked(),
            "源锁表满后必须升级为全局窗口，而不是继续吃进表项（内存上界）"
        );
        assert!(e.throttle_source_locks() <= e.limits().max_throttle_buckets);
        assert_eq!(
            e.authenticate("anyone", "10.0.9.10", "s3cret")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "全局窗口对所有主体生效，含正确令牌"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_transport_address_is_refused_before_the_throttle() {
        // `source` 本批被升格成归属凭证与额度键，空串就不能当身份用：把它记进节流表
        // 会留下一整桶 ("", "") 状态，谁都能往里灌失败、也谁都能替它还清。
        let dir = tmp("empty-source");
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(FileLimits::default(), vec![root], "s3cret").unwrap();
        assert_eq!(
            e.authenticate("someone", "", "s3cret")
                .map(|_| "ACCEPTED")
                .unwrap_err()
                .code,
            code::AUTH_DENIED,
            "空地址必须拒，哪怕令牌正确"
        );
        assert_eq!(e.throttle_buckets(), 0, "这条不进节流表");
        assert_eq!(e.throttle_failures(), 0);
        assert_eq!(
            e.audit().back().unwrap().result_code,
            code::AUTH_DENIED,
            "拒绝也要留一行（G21）"
        );
        assert!(
            e.authenticate("someone", "10.0.0.70", "s3cret").is_ok(),
            "同一条令牌的正常路径不受影响"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticate_compares_tokens_only_when_not_short_circuited() {
        // r1 起挂着的那句"没有任何断言约束 authenticate 真的用 constant_time_eq"，
        // 本批把**能被机器验证的那一半**闭掉：比较唯一入口是 `token_eq`，计数就在
        // 那里，于是两个方向都有对象——可比较的尝试恰好 +1，被锁定短路的尝试 +0。
        // 后者同时把"删掉锁定预检"（M10b）打红；"绕开唯一入口"（F）在这套 lints 下
        // 直接编不过。剩下那一半——入口内部换成长度相关的比较——本测试**不**背书，
        // 见 `token_eq` 文档与 G15 代价 (5)。
        let dir = tmp("compare-count");
        let l = FileLimits {
            lockout_after: 2,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let base = e.token_comparisons();
        assert_eq!(
            e.authenticate("u", "loopback", "nope")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::AUTH_DENIED
        );
        assert_eq!(
            e.token_comparisons(),
            base + 1,
            "一次普通拒绝就做了一次比较"
        );
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        assert_eq!(e.token_comparisons(), base + 2, "成功认证同样只比较一次");
        e.close_session(s, "loopback").unwrap();
        assert_eq!(
            e.authenticate("u", "loopback", "nope").unwrap_err().code,
            code::AUTH_DENIED,
            "夹具前提：第一条失败还没到阈值"
        );
        assert_eq!(
            e.authenticate("u", "loopback", "nope")
                .map(|_| "NONE")
                .unwrap_err()
                .code,
            code::THROTTLED,
            "第二条到阈值，报锁定"
        );
        assert_eq!(e.token_comparisons(), base + 4, "武装那一次仍然比较过");
        for _ in 0..4 {
            assert_eq!(
                e.authenticate("u", "loopback", "s3cret")
                    .map(|_| "NONE")
                    .unwrap_err()
                    .code,
                code::THROTTLED
            );
        }
        assert_eq!(
            e.token_comparisons(),
            base + 4,
            "锁定窗口内一次令牌比较都不许做——这就是短路在比较**之前**的证据"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_table_is_validated_at_construction() {
        // 评审 r6 NOTE-3：G12 写着"root 非空且不重复、read_only 组合同样校验"，
        // 但构造期这三条（重名 root、零 root、空令牌）都没有测试。
        let dir = tmp("roots");
        let a = SandboxRoot::open("dup", &dir, false).unwrap();
        let b = SandboxRoot::open("dup", &dir, true).unwrap();
        assert_eq!(
            FileEngine::new(FileLimits::default(), vec![a, b], "t")
                .map(|_| ())
                .unwrap_err()
                .code,
            code::CONFIG,
            "重名 root 必须拒启动"
        );
        assert_eq!(
            FileEngine::new(FileLimits::default(), vec![], "t")
                .map(|_| ())
                .unwrap_err()
                .code,
            code::CONFIG,
            "一个 root 都没有等于开了个没有授权面的文件面"
        );
        let solo = SandboxRoot::open("solo", &dir, false).unwrap();
        assert_eq!(
            FileEngine::new(FileLimits::default(), vec![solo], "")
                .map(|_| ())
                .unwrap_err()
                .code,
            code::CONFIG,
            "空令牌必须拒启动，而不是谁都能进"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_pages_are_charged_to_the_shared_budget() {
        // 评审 r4 R4-W-3：本片把 `list` 也接上了过账（引擎自己算得出 ack 长度），
        // 但当时没有任何测试覆盖——删掉那行 `charge_file` 不会让任何东西变红。
        // 这条测试的作用就是让那一行有杀伤力。
        let dir = tmp("list-budget");
        for i in 0..5 {
            std::fs::write(dir.join(format!("f{i}.txt")), "x").unwrap();
        }
        let l = FileLimits {
            chunk_bytes: 8,
            max_entries_per_page: 2,
            max_ack_bytes: 256,
            max_inflight_bytes_per_session: 512,
            max_buffered_amount: 512,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let p1 = e.list(s, "downloads", ".", 0).unwrap();
        assert_eq!(p1.entries.len(), 2);
        assert!(
            e.budget().file_buffered() > 0,
            "list 页必须过账——删掉 charge_file 这一行就红"
        );
        assert_eq!(e.inflight_bytes(s), e.budget().file_buffered());
        assert!(e.inflight_matches_budget(s));
        let p2 = e.list(s, "downloads", ".", p1.next_offset).unwrap();
        assert_eq!(p2.entries.len(), 2);
        let p3 = e.list(s, "downloads", ".", p2.next_offset).unwrap();
        assert_eq!(p3.entries.len(), 1);
        assert!(
            !p3.truncated && p3.is_complete_list,
            "1 条 < cap 不得谎报截断"
        );
        let err = e.list(s, "downloads", ".", 0).unwrap_err();
        assert_eq!(
            err.code,
            code::QUEUE_FULL,
            "共享预算满时 list 必须显式拒: {err}"
        );
        // 被拒的那页不能在任何地方返回出去，也不能留下占位条目。
        assert!(e.inflight_matches_budget(s));
        e.settle_file(s, e.budget().file_buffered());
        assert_eq!(e.inflight_bytes(s), 0);
        let again = e.list(s, "downloads", ".", 0).unwrap();
        assert_eq!(again.entries.len(), 2, "腾出预算后必须能重新读");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_refuses_to_stall_on_an_unrenderable_entry() {
        // 评审 r5 R5-W-3：ack 下限只保证"信封 + 一条空名条目"放得下，长文件名
        // 仍可能一条都塞不进。返回"0 条目但 truncated=true"等于让 `next_offset`
        // 停在原地——客户端永远翻不过这一页，而看起来什么都没失败。必须显式拒。
        let dir = tmp("list-stall");
        // 200 字节：在 Linux 的 255 字节 NAME_MAX 之内，又足以塞不进这条 ack 预算。
        let long_name = "n".repeat(200);
        std::fs::write(dir.join(&long_name), "x").unwrap();
        let l = FileLimits {
            max_entries_per_page: 8,
            max_ack_bytes: LIST_ACK_ENVELOPE_BYTES + ENTRY_ACK_OVERHEAD_BYTES + 64,
            max_buffered_amount: 128 * 1024,
            max_inflight_bytes_per_session: 128 * 1024,
            chunk_bytes: 8,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let err = e.list(s, "downloads", ".", 0).unwrap_err();
        assert_eq!(
            err.code,
            code::PAGE_TOO_LARGE,
            "0 条目页必须显式拒而不是谎报进展: {err}"
        );
        // "读完了"与"塞不进任何条目"必须是两回事：越过末尾是 Ok + complete
        // （客户端据此前进），而 0 条目且仍有剩余必须是显式错误。
        let past_end = e.list(s, "downloads", ".", 1).unwrap();
        assert!(
            past_end.entries.is_empty() && !past_end.truncated && past_end.is_complete_list,
            "越过末尾应报完整，而不是假装截断"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_read_page_is_charged_to_the_shared_budget() {
        let dir = tmp("budget");
        std::fs::write(dir.join("f.bin"), vec![3u8; 256]).unwrap();
        // 预算只够两页：第三页必须显式 QUEUE_FULL，而不是静默排队。
        // per-session 上限与预算相等（G12 要求 inflight <= buffered），
        // 所以先扣的共享预算就是这里的约束。ack 下限由 G12 另管（>= 信封+一条目）。
        let l = FileLimits {
            chunk_bytes: 64,
            max_inflight_bytes_per_session: 128,
            max_ack_bytes: 128,
            max_buffered_amount: 128,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        assert!(e.read_page(s, "downloads", "f.bin", 0, 64).is_ok());
        assert!(e.read_page(s, "downloads", "f.bin", 64, 64).is_ok());
        assert_eq!(e.budget().buffered(), 128);
        let err = e.read_page(s, "downloads", "f.bin", 128, 64).unwrap_err();
        assert_eq!(err.code, code::QUEUE_FULL, "预算满必须显式拒绝，实际 {err}");
        assert_eq!(e.budget().file_drops, 1);
        // terminal 类优先：挤掉 file 消息也要成功送达。
        assert!(e.send_terminal(128).is_ok());
        assert_eq!(e.budget().terminal_drops, 0);
        assert_eq!(e.budget().file_drops, 3, "两条 64 字节页被挤掉");
        // 被挤掉的消息必须回冲它**自己会话**的额度（评审 r2 NEW-2 第 1 点）：
        // 上一版这里冻的是"inflight 仍是 64"，那锁住的是缺陷——客户端只能去 ack
        // 一份它从未收到的页才能恢复。
        assert_eq!(e.inflight_bytes(s), 0, "挤掉的消息不得继续占会话额度");
        assert!(e.inflight_matches_budget(s), "过账与额度必须同步");
        // 冲刷终端字节后，拉式下载才能继续取下一页。
        e.settle_terminal(128);
        assert!(e.read_page(s, "downloads", "f.bin", 128, 64).is_ok());
        assert!(e.inflight_matches_budget(s));
        e.settle_file(s, 64);
        assert_eq!(e.inflight_bytes(s), 0, "对端 ack 才释放额度");
        assert!(e.inflight_matches_budget(s));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_session_inflight_ceiling_is_enforced_by_the_engine() {
        let dir = tmp("inflight");
        std::fs::write(dir.join("f.bin"), vec![9u8; 256]).unwrap();
        // G12 新增的配对约束（评审 r5 R5-W-3）：`max_ack_bytes ≤ inflight`，所以
        // 会话上限不可能低于一条 ack 的下限 124——用 128，共享预算给到 4096，
        // 让 per-session 上限成为**唯一**生效的约束。
        let l = FileLimits {
            chunk_bytes: 8,
            max_inflight_bytes_per_session: 128,
            max_ack_bytes: 128,
            max_buffered_amount: 4096,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        for page in 0..16 {
            e.read_page(s, "downloads", "f.bin", page * 8, 8).unwrap();
        }
        assert_eq!(e.inflight_bytes(s), 128);
        assert!(
            e.budget().buffered() < e.limits().max_buffered_amount,
            "夹具前提：共享预算还宽裕，绑住它的只能是要断言的那条上限"
        );
        let err = e.read_page(s, "downloads", "f.bin", 128, 8).unwrap_err();
        assert_eq!(
            err.code,
            code::CAPACITY,
            "共享预算还空着，per-session 上限必须独立生效"
        );
        // 评审 r4 R4-W-2：上一版处置清单声称"每次拒绝之后不变量仍成立"，但仓里
        // 并没有这条断言——删掉 charge_file 的 unpush_file 回滚，本测试照样绿
        // （残留条目会被后面的 settle_file 一并冲掉）。所以这里必须在**拒绝之后、
        // 任何 settle 之前**断言不变量：回滚丢了就是 136/128 背离。
        assert_eq!(e.budget().buffered(), 128, "被拒的 8 字节不得占预算");
        assert!(
            e.inflight_matches_budget(s),
            "CAPACITY 拒绝之后共享预算与会话额度必须仍一致（回滚有效性）"
        );
        // 释放后同一条流可以继续，说明上限不是"一次性配额"。
        e.settle_file(s, 128);
        assert_eq!(e.inflight_bytes(s), 0);
        assert!(e.read_page(s, "downloads", "f.bin", 128, 8).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_does_not_truncate_missing_multi_segment_paths() {
        let dir = tmp("resolve");
        std::fs::create_dir_all(dir.join("a")).unwrap();
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        // 旧实现遇到第一个缺失分量就 break，`a/b/c` 被截断成 `a`：
        // 上传因此能"成功"发布到错误前缀且不报错（评审 F4）。
        assert_eq!(
            root.resolve("a/b/c").unwrap(),
            dir.join("a").join("b").join("c"),
            "缺失分量必须继续按字面解析，而不是截断"
        );
        assert_eq!(root.resolve("x/y/z").unwrap(), dir.join("x/y/z"));
        assert_eq!(root.resolve("./a/./b").unwrap(), dir.join("a/b"));
        // 已存在的分量仍然逐个查符号链接：缺失不能变成检查的豁免。
        // （Windows 上建目录符号链接需要特权，与既有的
        // `symlink_component_is_refused_on_every_verb` 同一限制。）
        #[cfg(unix)]
        {
            std::fs::create_dir_all(dir.join("link-target")).unwrap();
            std::os::unix::fs::symlink(dir.join("link-target"), dir.join("a/escape")).unwrap();
            assert_eq!(
                root.resolve("a/escape/deep").unwrap_err().code,
                code::SYMLINK_ESCAPE
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_into_a_missing_intermediate_directory_fails_loudly() {
        let dir = tmp("upload-missing");
        std::fs::create_dir_all(dir.join("up")).unwrap();
        let root = SandboxRoot::open("uploads", &dir, false).unwrap();
        let mut e = FileEngine::new(FileLimits::default(), vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let err = e.open_upload(s, "uploads", "a/b/c.bin", None).unwrap_err();
        assert_eq!(
            err.code,
            code::NOT_FOUND,
            "中间目录不存在必须显式拒绝，实际 {err}"
        );
        // 拒绝后不得留下任何字节：既没有错误前缀下的文件，也没有 `.part`。
        assert!(!dir.join("a").exists(), "绝不能只在 `a` 下创建东西");
        let leftovers: Vec<_> = walkdir(&dir)
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        assert!(leftovers.is_empty(), "残留中转物: {leftovers:?}");
        // mkdir 建出前缀之后，同一条路径必须能正常上传并发布到 `a/b/c.bin`。
        e.mkdir(s, "uploads", "a/b").unwrap();
        let id = e.open_upload(s, "uploads", "a/b/c.bin", Some(4)).unwrap();
        e.stage_chunk(s, id, 0, b"abcd").unwrap();
        let published = e.commit_upload(s, "uploads", id, None).unwrap();
        assert_eq!(published, "a/b/c.bin");
        assert_eq!(std::fs::read(dir.join("a/b/c.bin")).unwrap(), b"abcd");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offsets_are_checked_and_pages_are_capped() {
        let dir = tmp("page");
        std::fs::write(dir.join("f.bin"), vec![7u8; 10]).unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        assert_eq!(
            e.read_page(s, "downloads", "f.bin", u64::MAX, 4)
                .unwrap_err()
                .code,
            code::OVERFLOW
        );
        let big = e.limits().chunk_bytes + 1;
        assert_eq!(
            e.read_page(s, "downloads", "f.bin", 0, big)
                .unwrap_err()
                .code,
            code::PAGE_TOO_LARGE
        );
        let p = e.read_page(s, "downloads", "f.bin", 0, 4).unwrap();
        assert_eq!((p.bytes.len(), p.next_offset, p.eof), (4, 4, false));
        // one handle per (session, path): chunks must not multiply handles
        for _ in 0..8 {
            let _ = e.read_page(s, "downloads", "f.bin", 0, 4).unwrap();
        }
        let (live, peak) = e.handle_stats();
        assert_eq!(live, 0, "每个分页读完即释放句柄，不得跨调用驻留");
        assert!(peak <= 1, "同步读单次最多一个句柄，peak {peak}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_page_reports_truncation_and_is_never_marked_complete() {
        let dir = tmp("list");
        for i in 0..5 {
            std::fs::write(dir.join(format!("f{i}.txt")), "x").unwrap();
        }
        let l = FileLimits {
            max_entries_per_page: 2,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let p = e.list(s, "downloads", ".", 0).unwrap();
        assert_eq!(p.entries.len(), 2);
        assert!(p.truncated);
        assert!(!p.is_complete_list);
        assert_eq!(p.next_offset, 2);
        let q = e.list(s, "downloads", ".", p.next_offset).unwrap();
        assert_eq!(q.entries.len(), 2);
        assert!(q.truncated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_sweep_uses_the_refreshed_field() {
        let dir = tmp("idle");
        let l = FileLimits {
            idle_timeout: Duration::from_millis(20),
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let st = e.open_upload(s, "downloads", "x.bin", None).unwrap();
        e.stage_chunk(s, st, 0, b"abc").unwrap();
        std::thread::sleep(Duration::from_millis(40));
        // activity after the window must have refreshed the swept field
        let _ = e.stat(s, "downloads", "x.bin");
        assert!(e.sweep_idle(Instant::now()).is_empty());
        std::thread::sleep(Duration::from_millis(40));
        // 评审 r5 N-8：这里也要断言"恰好一行"，不只是"这一行存在"。
        let before_sweep = e.audit().len();
        assert_eq!(e.sweep_idle(Instant::now()), vec![s]);
        assert_eq!(
            e.audit().len(),
            before_sweep + 1,
            "动作 idle_recycle 必须恰好留一行审计"
        );
        assert_eq!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|d| d.file_name().to_string_lossy().contains("nexus-part"))
                .count(),
            0,
            "recycling must not leave .part behind"
        );
        // 回收同样要留一行审计（评审 r3 R3-NEW-3：G21 说"逐个动词断言"，
        // 而 idle_recycle 这行过去没有任何断言覆盖）。
        let rec = e.audit().back().unwrap();
        assert_eq!(rec.action, "idle_recycle");
        assert_eq!(rec.result_code, code::IDLE);
        assert_eq!(rec.principal, "u", "回收行必须能归因到主体");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_verb_is_audited_including_refusals() {
        let dir = tmp("audit");
        std::fs::write(dir.join("f.txt"), "hello").unwrap();
        std::fs::write(dir.join("taken.txt"), "x").unwrap();
        let mut e = engine(&dir);

        // 旧断言只看"某个码出现过"，删掉任意一处 `record` 都不会红（评审：装饰测试）。
        // 这里逐个动作断言"恰好一行、action 对、码对、principal 非空"。
        macro_rules! audited {
            ($label:expr, $want:expr, $call:expr) => {{
                let before = e.audit().len();
                let outcome = $call;
                assert_eq!(
                    e.audit().len(),
                    before + 1,
                    "动作 {} 必须恰好留一行审计",
                    $label
                );
                let rec = e.audit().back().unwrap();
                assert_eq!(rec.action, $label, "审计行的 action");
                assert_eq!(rec.result_code, $want, "{} 的结果码", $label);
                assert!(!rec.principal.is_empty(), "{} 的审计行必须能归因", $label);
                outcome
            }};
        }

        let _ = audited!(
            "authenticate",
            code::AUTH_DENIED,
            e.authenticate("u", "loopback", "bad")
                .map(|_| ())
                .unwrap_err()
        );
        let s = audited!(
            "authenticate",
            "OK",
            e.authenticate("u", "loopback", "s3cret")
        )
        .unwrap();

        let _ = audited!(
            "stat",
            code::NOT_FOUND,
            e.stat(s, "downloads", "missing.bin").map(|_| ())
        );
        let _ = audited!(
            "list",
            code::NOT_FOUND,
            e.list(s, "downloads", "missing-dir", 0).map(|_| ())
        );
        let _ = audited!("list", "OK", e.list(s, "downloads", ".", 0).map(|_| ()));
        let _ = audited!(
            "read",
            code::PAGE_TOO_LARGE,
            e.read_page(s, "downloads", "f.txt", 0, e.limits().chunk_bytes + 1)
                .map(|_| ())
        );
        let _ = audited!(
            "read",
            code::NOT_FOUND,
            e.read_page(s, "downloads", "missing.bin", 0, 4).map(|_| ())
        );
        let _ = audited!(
            "read",
            "OK",
            e.read_page(s, "downloads", "f.txt", 0, 4).map(|_| ())
        );
        let _ = audited!(
            "open_upload",
            code::EXISTS,
            e.open_upload(s, "downloads", "taken.txt", Some(1))
                .map(|_| ())
        );
        let _ = audited!(
            "open_upload",
            code::CAPACITY,
            e.open_upload(
                s,
                "downloads",
                "big.bin",
                Some(e.limits().max_upload_bytes + 1)
            )
            .map(|_| ())
        );
        let _ = audited!(
            "open_upload",
            code::NOT_FOUND,
            e.open_upload(s, "downloads", "no/such/dir/x.bin", None)
                .map(|_| ())
        );
        let id = audited!(
            "open_upload",
            "OK",
            e.open_upload(s, "downloads", "ok.bin", Some(4))
        )
        .unwrap();
        let _ = audited!(
            "stage_chunk",
            code::INTEGRITY,
            e.stage_chunk(s, id, 9, b"abcd").map(|_| ())
        );
        assert_eq!(
            e.audit().back().unwrap().root,
            "downloads",
            "stage_chunk 的拒绝行必须带 root（评审 r6 WARN-1：过去写死空串）"
        );
        let before = e.audit().len();
        e.stage_chunk(s, id, 0, b"ab").unwrap();
        assert_eq!(
            e.audit().len(),
            before,
            "逐片成功不得灌满审计环（设计取舍见 stage_chunk 文档）"
        );
        let _ = audited!(
            "commit",
            code::INTEGRITY,
            e.commit_upload(s, "downloads", id, None).map(|_| ())
        );
        // `abort_upload` 返回单元值，走不了上面的宏（`let outcome = …` 会被
        // clippy 的 let_unit_value 拒），所以这里手写下同样的"恰好一行"断言。
        let before_abort = e.audit().len();
        e.abort_upload(s, id);
        assert_eq!(
            e.audit().len(),
            before_abort + 1,
            "动作 abort_upload 必须恰好留一行审计"
        );
        let rec = e.audit().back().unwrap();
        assert_eq!(rec.action, "abort_upload");
        assert_eq!(rec.result_code, "OK");
        assert!(!rec.principal.is_empty(), "abort_upload 的审计行必须能归因");
        let _ = audited!(
            "ack_staged",
            code::NOT_FOUND,
            e.ack_staged(s, 999_999).map(|_| ())
        );
        let _ = audited!(
            "mkdir",
            code::OUTSIDE_ROOT,
            e.mkdir(s, "downloads", "../escape").map(|_| ())
        );
        // mkdir 允许一次建出整条链（`a/b`），所以它的拒绝来自越界而不是"父目录不存在"。
        let _ = audited!("mkdir", "OK", e.mkdir(s, "downloads", "a/b").map(|_| ()));
        assert!(dir.join("a/b").is_dir(), "mkdir 必须建出整条缺失链");
        // 评审 r4 R4-W-4：G21 列出 12 个动词，而上一版只有拒绝侧被断言，
        // 成功侧的 `stat`/`remove`/`commit`/`close_session` 一行都没验过——
        // 删掉包装层的 `Ok` 分支只有 `list` 会红。这里把成功侧逐个钉上。
        let _ = audited!("stat", "OK", e.stat(s, "downloads", "f.txt").map(|_| ()));
        std::fs::write(dir.join("gone.txt"), "bye").unwrap();
        let _ = audited!(
            "remove",
            "OK",
            e.remove(s, "downloads", "gone.txt", false).map(|_| ())
        );
        let cid = e.open_upload(s, "downloads", "c1.bin", Some(2)).unwrap();
        e.stage_chunk(s, cid, 0, b"hi").unwrap();
        let _ = audited!("commit", "OK", e.commit_upload(s, "downloads", cid, None));
        assert_eq!(std::fs::read(dir.join("c1.bin")).unwrap(), b"hi");
        let _ = audited!(
            "remove",
            code::NOT_FOUND,
            e.remove(s, "downloads", "missing.bin", false).map(|_| ())
        );
        let _ = audited!(
            "rename",
            code::NOT_FOUND,
            e.rename(s, "downloads", "missing.bin", "x.bin").map(|_| ())
        );
        let _ = audited!(
            "rename",
            code::EXISTS,
            e.rename(s, "downloads", "f.txt", "taken.txt").map(|_| ())
        );
        let _ = audited!(
            "rename",
            "OK",
            e.rename(s, "downloads", "f.txt", "r.txt").map(|_| ())
        );

        // `close_session` 同样返回单元值，手写"恰好一行"的断言（同上）。
        let before_close = e.audit().len();
        e.close_session(s, "loopback").unwrap();
        assert_eq!(
            e.audit().len(),
            before_close + 1,
            "动作 close_session 必须恰好留一行审计"
        );
        let rec = e.audit().back().unwrap();
        assert_eq!(rec.action, "close_session");
        assert_eq!(rec.result_code, "OK");
        assert_eq!(rec.principal, "u");

        // 审计环有界：灌满之后丢最旧并计数，不是无限增长。
        let s2 = e.authenticate("u", "loopback", "s3cret").unwrap();
        let cap = AUDIT_CAPACITY;
        for _ in 0..(cap + 50) {
            let _ = e.stat(s2, "downloads", "missing.bin");
        }
        assert!(e.audit().len() <= cap, "审计日志必须有界");
        assert!(e.audit_dropped() >= 50, "溢出必须可观测");
        assert_eq!(e.audit().back().unwrap().result_code, code::NOT_FOUND);

        // 评审 r5 R5-W-4：光有"行数有界"不算数。`principal` 在令牌校验**之前**
        // 就被写下，`rel` 也来自调用方——不裁长度的话未认证者可以把每一行撑到
        // 任意大，"用审计把内存打满"那条路径只是换了形状。这里断言按**字节**封顶，
        // 且截断是可见的（不是悄悄改写内容）。
        let long = "x".repeat(4000);
        for i in 0..20 {
            let _ = e.authenticate(&format!("{long}{i}"), &long, "wrong");
        }
        let _ = e.stat(s2, "downloads", &long);
        // 环已经饱和（前面灌了 8242 次），所以这里不能断言"长度又涨了 21"——
        // 饱和环的行长恒等于容量，能断言的是**最后 21 行**的字节上界与内容。
        assert_eq!(e.audit().len(), AUDIT_CAPACITY, "饱和后行数就停在容量");
        for rec in e.audit().iter().rev().take(21) {
            assert!(
                rec.principal.len() <= AUDIT_FIELD_MAX_BYTES + 16,
                "principal 必须按字节封顶，实际 {}",
                rec.principal.len()
            );
            assert!(
                rec.rel.len() <= AUDIT_FIELD_MAX_BYTES + 16,
                "rel 必须按字节封顶，实际 {}",
                rec.rel.len()
            );
        }
        assert!(
            e.audit()
                .iter()
                .rev()
                .take(20)
                .any(|r| r.principal.contains("[+")),
            "截断必须留下可见标记，不能静默改写"
        );

        // 未知会话号的 close 也要留一行（评审 r5 N-8：否则"漏记结构性不可发生"
        // 只对已知会话成立）。环此时已饱和 ⇒ 按**尾部内容**断言，不断言行数增长。
        let _ = e.close_session(999_999, "loopback");
        let rec = e.audit().back().unwrap();
        assert_eq!(rec.action, "close_session");
        assert_eq!(
            rec.result_code,
            code::NOT_FOUND,
            "未知会话的 close 记 NOT_FOUND"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_cannot_be_redirected_to_another_root() {
        // 评审 r2 NEW-1：commit 曾经只看调用方当场给的 root 参数，既不查可写、
        // 也不查后端，而流本身不记它开在哪个 root 上。
        let dir = tmp("commit-root");
        let ro = tmp("commit-ro");
        let writable = SandboxRoot::open("w", &dir, false).unwrap();
        let readonly = SandboxRoot::open("ro", &ro, true).unwrap();
        let remote = SandboxRoot::open_sftp("remote", "/home/user/files", false).unwrap();
        let mut e = FileEngine::new(
            FileLimits::default(),
            vec![writable, readonly, remote],
            "s3cret",
        )
        .unwrap();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let id = e.open_upload(s, "w", "new.bin", Some(4)).unwrap();
        e.stage_chunk(s, id, 0, b"abcd").unwrap();

        assert_eq!(
            e.commit_upload(s, "ro", id, None).unwrap_err().code,
            code::OUTSIDE_ROOT,
            "把可写根上开的流提交进只读根必须被拒"
        );
        assert_eq!(
            std::fs::read_dir(&ro).unwrap().flatten().count(),
            0,
            "只读根里不得出现任何字节"
        );
        assert_eq!(
            e.commit_upload(s, "remote", id, None).unwrap_err().code,
            code::OUTSIDE_ROOT,
            "SFTP 根的远端路径绝不能进本地解析器"
        );
        // 拒绝不能吃掉流：回到真正的 root 仍要能发布。
        assert_eq!(
            e.commit_upload(s, "w", id, None).unwrap(),
            "new.bin",
            "提交必须落在打开它的那个 root"
        );
        assert_eq!(std::fs::read(dir.join("new.bin")).unwrap(), b"abcd");
        assert_eq!(
            e.open_upload(s, "ro", "x.bin", None).unwrap_err().code,
            code::READ_ONLY
        );
        e.close_session(s, "loopback").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ro);
    }

    #[test]
    fn session_teardown_releases_the_shared_budget() {
        // 评审 r2 NEW-2 第 2 点：close/sweep 曾经只丢 FileSession，从不冲共享预算，
        // 于是"认证→读两页→断线"两轮就把**全节点**的文件类发送预算永久钉死。
        let dir = tmp("teardown");
        std::fs::write(dir.join("f.bin"), vec![1u8; 256]).unwrap();
        let l = FileLimits {
            chunk_bytes: 64,
            max_inflight_bytes_per_session: 128,
            max_ack_bytes: 128,
            max_buffered_amount: 128,
            idle_timeout: Duration::from_millis(20),
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let s1 = e.authenticate("u", "10.0.0.1", "s3cret").unwrap();
        e.read_page(s1, "downloads", "f.bin", 0, 64).unwrap();
        e.read_page(s1, "downloads", "f.bin", 64, 64).unwrap();
        assert_eq!(e.budget().buffered(), 128);

        let s2 = e.authenticate("u", "10.0.0.2", "s3cret").unwrap();
        assert_eq!(
            e.read_page(s2, "downloads", "f.bin", 0, 64)
                .unwrap_err()
                .code,
            code::QUEUE_FULL,
            "预算被 s1 占满时第二个会话必须显式排队失败"
        );
        e.close_session(s1, "10.0.0.1").unwrap();
        assert_eq!(e.budget().buffered(), 0, "会话拆除必须归还共享预算");
        assert!(e.read_page(s2, "downloads", "f.bin", 0, 64).is_ok());

        // 闲置回收走同一条释放路径。
        e.settle_file(s2, 64);
        e.read_page(s2, "downloads", "f.bin", 64, 64).unwrap();
        assert_eq!(e.budget().buffered(), 64);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(e.sweep_idle(Instant::now()), vec![s2]);
        assert_eq!(e.budget().buffered(), 0, "闲置回收同样必须归还共享预算");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn throttle_fails_closed_when_the_table_is_full() {
        // 评审 r2 NEW-3：表满后旧实现只累加私有计数、从不写 `locked`，
        // `authenticate` 却继续比令牌 ⇒ 轮换 principal 就买到无限次猜测。
        let dir = tmp("throttle-full");
        let l = FileLimits {
            max_throttle_buckets: 8,
            lockout_after: 3,
            // 上界 8×3：单源洪水（12 条）要先撞上表满，而不是源锁。
            max_failures_per_source: 24,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        for i in 0..e.limits().max_throttle_buckets {
            let _ = e.authenticate(&format!("p{i}"), "10.0.0.9", "wrong");
        }
        assert_eq!(e.throttle_buckets(), e.limits().max_throttle_buckets);
        assert_eq!(e.throttle_overflow(), 0);
        assert!(
            !e.throttle_globally_locked(),
            "填满但未超阈值时不应全局锁定"
        );
        for _ in 0..e.limits().lockout_after {
            let _ = e.authenticate("rotating", "10.0.0.9", "wrong");
        }
        assert!(e.throttle_overflow() >= e.limits().lockout_after);
        assert!(
            e.throttle_globally_locked(),
            "溢出必须升级为可观测的全局锁定窗口"
        );
        // 关键：全新 principal + **正确令牌**也必须被拒（旧实现这里返回 Ok）。
        assert_eq!(
            e.authenticate("brand-new", "10.0.0.9", "s3cret")
                .unwrap_err()
                .code,
            code::THROTTLED
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_quotas_are_admission_checks() {
        // 评审 r2 NEW-4：max_sessions / max_browser_sessions 过去只出现在
        // `validate()` 的两两比较里，从不参与准入 ⇒ 一个合法令牌能开无限会话。
        let dir = tmp("admission");
        let l = FileLimits {
            max_sessions: 3,
            max_browser_sessions: 2,
            ..Default::default()
        };
        let root = SandboxRoot::open("downloads", &dir, false).unwrap();
        let mut e = FileEngine::new(l, vec![root], "s3cret").unwrap();
        let a = e.authenticate("u", "10.0.0.1", "s3cret").unwrap();
        let b = e.authenticate("u", "10.0.0.1", "s3cret").unwrap();
        assert_eq!(
            e.authenticate("u", "10.0.0.1", "s3cret").unwrap_err().code,
            code::CAPACITY,
            "同一 peer 超过 max_browser_sessions 必须拒"
        );
        let c = e.authenticate("u", "10.0.0.2", "s3cret").unwrap();
        assert_eq!(
            e.authenticate("u", "10.0.0.3", "s3cret").unwrap_err().code,
            code::CAPACITY,
            "全局 max_sessions 同样必须拒"
        );
        // 释放的额度必须可复用，不是"一次性配额"。
        e.close_session(a, "10.0.0.1").unwrap();
        e.close_session(b, "10.0.0.1").unwrap();
        e.close_session(c, "10.0.0.2").unwrap();
        assert!(e.authenticate("u", "10.0.0.3", "s3cret").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_records_are_snapshottable() {
        // 评审 r2 W-1：`#[derive(Debug, Clone, PartialEq, Eq)]` 曾被误写进 `///`
        // 注释里，四个 derive 全部静默消失（照样能编译，因为没人 clone）。
        let dir = tmp("audit-derive");
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let rec = e.audit().back().unwrap().clone();
        assert_eq!(&rec, e.audit().back().unwrap());
        assert!(format!("{rec:?}").contains("authenticate"));
        assert_eq!(rec.principal, "u", "principal 必须是真实主体");
        e.close_session(s, "loopback").unwrap();
        assert_eq!(
            e.audit().back().unwrap().action,
            "close_session",
            "拆除会话也要留痕（r2 W-5）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_a_file_is_non_overwriting_and_leaves_one_name() {
        // 评审 r2 W-3：`dst.exists()` 之后 `rename(2)` 是**静默替换**，
        // 窗口里目标出现就覆盖原字节。文件因此改走 hard_link + unlink。
        let dir = tmp("rename-atomic");
        std::fs::write(dir.join("a.txt"), "AAA").unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        assert!(e.rename(s, "downloads", "a.txt", "b.txt").is_ok());
        assert!(!dir.join("a.txt").exists(), "改名后只能剩一个名字");
        assert_eq!(std::fs::read_to_string(dir.join("b.txt")).unwrap(), "AAA");
        // 目标在检查之后、发布之前出现：必须 EXISTS 且原字节一字未动。
        std::fs::write(dir.join("c.txt"), "CCC").unwrap();
        std::fs::write(dir.join("d.txt"), "SRC").unwrap();
        assert!(e.rename(s, "downloads", "d.txt", "e.txt").is_ok());
        assert_eq!(
            e.rename(s, "downloads", "e.txt", "c.txt").unwrap_err().code,
            code::EXISTS
        );
        assert_eq!(std::fs::read_to_string(dir.join("c.txt")).unwrap(), "CCC");
        assert_eq!(std::fs::read_to_string(dir.join("e.txt")).unwrap(), "SRC");
        // 目录改名仍走 rename(2)：目标存在时靠前置检查拒，但窗口是**声明过的**
        // （std 下 `hard_link` 对目录失败，拿不到原子无覆盖），见 G13/§18.4。
        e.mkdir(s, "downloads", "d1").unwrap();
        e.mkdir(s, "downloads", "d2").unwrap();
        assert_eq!(
            e.rename(s, "downloads", "d1", "d2").unwrap_err().code,
            code::EXISTS,
            "目录改名撞上已存在目标也必须拒（前置检查这一半）"
        );
        assert!(dir.join("d1").is_dir() && dir.join("d2").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_registry_ceiling_is_reachable() {
        // 评审 r2 W-9：`read_page` 在同一次调用里 acquire+release，`live()` 恒 0，
        // 所以配额分支在产品路径上**结构不可达**——G16 的句柄防线是意外成立的。
        // 这里直接测注册表本身，让 `max_read_handles` 至少有一条真会红的断言；
        // OS 句柄层面（/proc/self/fd）仍未验，记在 M1 剩余项。
        let mut reg = HandleRegistry::new(2);
        assert_eq!(reg.acquire(1, "/a").unwrap(), 1);
        assert_eq!(reg.acquire(1, "/a").unwrap(), 1, "同会话同路径不得重复计数");
        assert_eq!(reg.acquire(1, "/b").unwrap(), 2);
        assert_eq!(reg.acquire(1, "/c").unwrap_err().code, code::CAPACITY);
        reg.release(1, "/a");
        assert_eq!(reg.live(), 1);
        assert_eq!(reg.acquire(1, "/c").unwrap(), 2);
        assert!(reg.peak >= 2, "峰值必须记录实际并发，而不是恒 1");
    }

    #[test]
    fn every_validate_rule_has_a_red_test() {
        // 评审 r2 W-8 补了测试，评审 r3 R3-NEW-3 又指出这些红**不代表各自那条规则**：
        // 例如 `handles < sessions` 的夹具会先在 `chunk > inflight` 上短路，删掉
        // 句柄那条规则它照样红。所以这里每条都断言错误消息里的规则名，且夹具必须
        // 只违反自己那一条。
        let cases = [
            (
                "no limit may be zero",
                FileLimits {
                    max_entries_per_page: 0,
                    ..Default::default()
                },
            ),
            (
                // 评审 r4 R4-NEW-1：本批新加的时长字段漏在零值检查之外，
                // `lockout_window = 0` 会让每次锁定刚写下就过期，节流形同不存在。
                "lockout_window must not be zero",
                FileLimits {
                    lockout_window: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "idle_timeout must not be zero",
                FileLimits {
                    idle_timeout: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "no limit may be zero: a zero ceiling silently disables its gate",
                FileLimits {
                    max_upload_bytes: 0,
                    ..Default::default()
                },
            ),
            (
                "no limit may be zero: a zero ceiling silently disables its gate",
                FileLimits {
                    max_rehash_bytes_per_stream: 0,
                    ..Default::default()
                },
            ),
            (
                "max_browser_sessions must not exceed",
                FileLimits {
                    max_browser_sessions: 8,
                    ..Default::default()
                },
            ),
            (
                // 单源额度的两条交叉规则各有一个只违反自己的夹具（G12 的口径：
                // 每条规则都要能被单独跑红，否则"逐条有测"又是空话）。
                "max_failures_per_source must be >= lockout_after",
                FileLimits {
                    max_failures_per_source: 4,
                    ..Default::default()
                },
            ),
            (
                "max_failures_per_source must be <= max_throttle_buckets * lockout_after",
                FileLimits {
                    max_throttle_buckets: 4,
                    max_failures_per_source: 40,
                    ..Default::default()
                },
            ),
            (
                "chunk_bytes must be <= max_buffered_amount",
                FileLimits {
                    chunk_bytes: 256 * 1024,
                    max_ack_bytes: 32 * 1024,
                    max_inflight_bytes_per_session: 256 * 1024,
                    max_buffered_amount: 128 * 1024,
                    ..Default::default()
                },
            ),
            (
                "chunk_bytes must be <= max_inflight_bytes_per_session",
                FileLimits {
                    chunk_bytes: 64 * 1024,
                    max_inflight_bytes_per_session: 32 * 1024,
                    ..Default::default()
                },
            ),
            (
                // 注：加了 `max_ack_bytes ≤ max_inflight_bytes_per_session` 之后，
                // `max_ack_bytes ≤ max_buffered_amount` 已成为**被蕴含**的约束
                // （ack ≤ inflight ≤ buffered 两段链），它作为先写下的检查保留是
                // 纵深防御，但无法再构造"只违反它"的夹具——强行构造会同时违反
                // inflight ≤ buffered。这里验链条的后半段。
                "max_inflight_bytes_per_session must be <= max_buffered_amount",
                FileLimits {
                    max_ack_bytes: 32 * 1024,
                    max_inflight_bytes_per_session: 256 * 1024,
                    max_buffered_amount: 128 * 1024,
                    ..Default::default()
                },
            ),
            (
                // 评审 r5 R5-W-3：新加的计费量必须有配对约束，否则"配置自洽却
                // 永远无法完成一次 list"。
                "max_ack_bytes must be <= max_inflight_bytes_per_session",
                FileLimits {
                    max_ack_bytes: 128 * 1024,
                    max_inflight_bytes_per_session: 64 * 1024,
                    ..Default::default()
                },
            ),
            (
                // 评审 r5 R5-W-2：只封低边等于没封——同一片刚在 config.rs 里给
                // max_terminals 补了上界。时长参与 `Instant + Duration`。
                "lockout_window must be <= 24h",
                FileLimits {
                    lockout_window: Duration::from_secs(24 * 3600 + 1),
                    ..Default::default()
                },
            ),
            (
                "idle_timeout must be <= 24h",
                FileLimits {
                    idle_timeout: Duration::from_secs(24 * 3600 + 1),
                    ..Default::default()
                },
            ),
            (
                "max_ack_bytes must be >=",
                FileLimits {
                    max_ack_bytes: 100,
                    ..Default::default()
                },
            ),
            (
                "max_inflight_bytes_per_session must be <= max_buffered_amount",
                FileLimits {
                    max_inflight_bytes_per_session: 256 * 1024,
                    ..Default::default()
                },
            ),
            (
                "max_read_handles must be >=",
                FileLimits {
                    max_sessions: 8,
                    max_read_handles: 2,
                    max_browser_sessions: 2,
                    ..Default::default()
                },
            ),
        ];
        for (keyword, l) in cases {
            let err = l
                .validate()
                .expect_err(&format!("规则 {keyword:?} 必须拒启动"));
            assert_eq!(err.code, code::CONFIG, "{keyword} 的码");
            assert!(
                err.message.contains(keyword),
                "夹具本该触发 {keyword:?}，实际触发的是：{}",
                err.message
            );
        }
        // 反向：合法边界必须放行，否则上界就成了不可用的死配置。
        assert!(
            FileLimits {
                max_ack_bytes: LIST_ACK_ENVELOPE_BYTES + ENTRY_ACK_OVERHEAD_BYTES,
                max_buffered_amount: LIST_ACK_ENVELOPE_BYTES + ENTRY_ACK_OVERHEAD_BYTES,
                chunk_bytes: 8,
                max_inflight_bytes_per_session: LIST_ACK_ENVELOPE_BYTES + ENTRY_ACK_OVERHEAD_BYTES,
                max_read_handles: 4,
                max_sessions: 4,
                max_browser_sessions: 1,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn zero_byte_page_request_is_refused_not_stalling() {
        // 评审 r2 W-4：`max_bytes = 0` 会返回 `next_offset == offset` 的空页，
        // 客户端因此永远停在同一页 —— G17 的"next_offset 单调"被破坏。
        let dir = tmp("zero-page");
        std::fs::write(dir.join("f.bin"), vec![7u8; 10]).unwrap();
        let mut e = engine(&dir);
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let err = e.read_page(s, "downloads", "f.bin", 0, 0).unwrap_err();
        assert_eq!(
            err.code,
            code::PAGE_TOO_LARGE,
            "0 字节请求必须显式拒: {err}"
        );
        let p = e.read_page(s, "downloads", "f.bin", 0, 4).unwrap();
        assert!(p.next_offset > 0, "正常页的 next_offset 必须前进");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn part_creation_refuses_a_preplanted_symlink() {
        // `part_path` 的"不可预置"依赖一条 std 语义：O_CREAT|O_EXCL 遇到已存在的
        // 符号链接必须失败，而不是跟随它把字节写穿到链接目标（评审 F5）。
        // 这条测试锁住前提本身；父目录被换链接那一类 TOCTOU 由 reverify_parent
        // 事前/事后两次检查夹住，残余窗口写在 G13 与 PRODUCT §18.3。
        if !cfg!(unix) {
            eprintln!(
                "skip: Windows 建符号链接需要特权（见 symlink_component_is_refused_on_every_verb）"
            );
            return;
        }
        let dir = tmp("part-oexcl");
        let outside = tmp("part-outside");
        std::fs::write(outside.join("victim"), b"ORIGINAL").unwrap();
        let link = dir.join(".f.bin.nexus-part-deadbeef");
        std::os::unix::fs::symlink(outside.join("victim"), &link).unwrap();
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&link);
        assert!(opened.is_err(), "O_EXCL 必须拒绝已存在的符号链接");
        assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"ORIGINAL");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn constant_time_eq_distinguishes_lengths_and_prefixes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        // 诚实边界（评审：这是第二条装饰测试）：本测试能杀"长度不等提前返回 false"
        // 和"只比前缀"两种变异，但**杀不掉**"逐字节比较时提前 return"——那是
        // 时序侧信道，进程内无法可靠观测。该变异因此登记在 V2 §10 的
        // 变异可杀性清单里，按"评审目视 + 人工检查"处理，不谎称机器可验。
    }
}
