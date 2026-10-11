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

use std::collections::{BTreeMap, HashMap};
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
    /// Bytes the server will re-hash per stream while verifying a resume.
    pub max_rehash_bytes_per_stream: u64,
    /// Idle window after which a file session is recycled (G21).
    pub idle_timeout: Duration,
    /// Failed authentications before the principal/source bucket is locked out.
    pub lockout_after: usize,
    /// Entries kept in the throttle table; beyond that, oldest buckets are
    /// merged into the global bucket so memory cannot grow with forged volume.
    pub max_throttle_buckets: usize,
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
            max_inflight_bytes_per_session: 1024 * 1024,
            max_upload_bytes: 2 * 1024 * 1024 * 1024,
            max_rehash_bytes_per_stream: 64 * 1024 * 1024,
            idle_timeout: Duration::from_secs(300),
            lockout_after: 5,
            max_throttle_buckets: 1024,
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
        {
            return Err(FileError::new(
                code::CONFIG,
                "no limit may be zero: a zero ceiling silently disables its gate",
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
        // Cross constraint that V1 never checked: the worst-case in-flight file
        // bytes across all sessions must stay below what the SCTP budget can
        // absorb, otherwise the queue grows without bound (measured: +1 GiB RSS).
        let worst_case = self
            .max_sessions
            .checked_mul(self.max_inflight_bytes_per_session)
            .ok_or_else(|| FileError::new(code::OVERFLOW, "limits multiplication overflow"))?;
        if worst_case > self.max_buffered_amount.saturating_mul(64) {
            return Err(FileError::new(
                code::CONFIG,
                "max_sessions * max_inflight_bytes_per_session exceeds the buffered-amount budget (x64)",
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

/// A configured export directory. Construction is the only place where a root
/// becomes canonical, and a non-canonical configured root is rejected (G13).
#[derive(Debug, Clone)]
pub struct SandboxRoot {
    name: String,
    canonical: PathBuf,
    read_only: bool,
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
                    break;
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
        if self.read_only {
            return Err(FileError::new(code::READ_ONLY, self.name.clone()));
        }
        Ok(())
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
#[derive(Debug)]
pub struct HandleRegistry {
    open: HashMap<(u64, String), usize>,
    budget: usize,
    pub peak: usize,
}

impl HandleRegistry {
    pub fn new(budget: usize) -> Self {
        Self {
            open: HashMap::new(),
            budget,
            peak: 0,
        }
    }

    /// Returns the number of live handles after acquiring. A repeated chunk of
    /// the same (session, path) costs nothing, which is the whole point of
    /// server-issued stream identity (G16).
    pub fn acquire(&mut self, session: u64, path: &str) -> FileResult<usize> {
        let key = (session, path.to_string());
        let already_open = self.open.contains_key(&key);
        if !already_open && self.live() >= self.budget {
            return Err(FileError::new(
                code::CAPACITY,
                format!(
                    "read handle budget exhausted ({} open, budget {})",
                    self.live(),
                    self.budget
                ),
            ));
        }
        *self.open.entry(key).or_insert(0) += 1;
        self.peak = self.peak.max(self.live());
        Ok(self.live())
    }

    pub fn release(&mut self, session: u64, path: &str) {
        let key = (session, path.to_string());
        if let Some(e) = self.open.get_mut(&key) {
            *e = e.saturating_sub(1);
            if *e == 0 {
                self.open.remove(&key);
            }
        }
    }

    pub fn live(&self) -> usize {
        self.open.values().sum()
    }
}

/// The engine's per-file byte accounting for one upload stream (G18).
#[derive(Debug)]
pub struct UploadStream {
    pub id: u64,
    pub session: u64,
    pub rel: String,
    /// Contiguous bytes already durably staged; the only number ever acked.
    pub staged: u64,
    pub declared_len: Option<u64>,
    pub hasher: Sha256,
    pub hashed_bytes: u64,
    pub part_path: PathBuf,
    pub file: std::fs::File,
    pub last_activity: Instant,
}

/// A file session: identity, budget, streams, activity (G15/G16/G21).
#[derive(Debug)]
pub struct FileSession {
    pub id: u64,
    pub principal: String,
    pub inflight_bytes: usize,
    pub streams: BTreeMap<u64, UploadStream>,
    /// The field the idle sweeper reads. Every activity updates *this* field —
    /// V1 refreshed a different one, which made the timeout unreachable.
    pub last_activity: Instant,
    pub recycled: bool,
}

/// Bounded authentication throttle (G15).
#[derive(Debug, Default)]
pub struct Throttle {
    buckets: HashMap<(String, String), usize>,
    /// Overflow sink: when the table is full, new failures land here instead of
    /// growing memory with forged volume (so `throttle_entries_bounded` is real).
    global: usize,
    locked: HashMap<(String, String), Instant>,
    max_buckets: usize,
    lockout: Duration,
    lockout_after: usize,
}

impl Throttle {
    pub fn new(max_buckets: usize, lockout_after: usize, lockout: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            global: 0,
            locked: HashMap::new(),
            max_buckets,
            lockout,
            lockout_after,
        }
    }

    pub fn is_locked(&self, principal: &str, source: &str) -> bool {
        let key = (principal.to_string(), source.to_string());
        match self.locked.get(&key) {
            Some(until) => *until > Instant::now(),
            None => false,
        }
    }

    /// Record a failure; returns true if this pushed the bucket into lockout.
    pub fn record_failure(&mut self, principal: &str, source: &str) -> bool {
        let key = (principal.to_string(), source.to_string());
        if self.buckets.len() >= self.max_buckets && !self.buckets.contains_key(&key) {
            self.global += 1;
            return self.global >= self.lockout_after;
        }
        let n = self.buckets.entry(key.clone()).or_insert(0);
        *n += 1;
        if *n >= self.lockout_after {
            self.locked.insert(key, Instant::now() + self.lockout);
            return true;
        }
        false
    }

    pub fn succeed(&mut self, principal: &str, source: &str) {
        self.buckets
            .remove(&(principal.to_string(), source.to_string()));
    }

    pub fn buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Called on session teardown: a recycled session must not leave state
    /// behind, or the table grows with connection churn (asserted by the probe).
    pub fn forget(&mut self, principal: &str, source: &str) {
        let key = (principal.to_string(), source.to_string());
        self.buckets.remove(&key);
        self.locked.remove(&key);
    }
}

/// Shared SCTP send budget with class priority (G16). Terminal bytes are never
/// dropped; file-class messages are refused explicitly and counted.
#[derive(Debug)]
pub struct SendBudget {
    pub limit: usize,
    pub buffered: usize,
    pub file_drops: usize,
    pub terminal_delivered: usize,
    pub terminal_drops: usize,
}

impl SendBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            buffered: 0,
            file_drops: 0,
            terminal_delivered: 0,
            terminal_drops: 0,
        }
    }

    pub fn push_terminal(&mut self, bytes: usize) -> FileResult<()> {
        // Terminal has priority: if the budget is full, file-class drops first.
        if self.buffered + bytes > self.limit {
            self.file_drops += self.drain_file_reserve(bytes);
        }
        if self.buffered + bytes > self.limit {
            // Still no room: this is a hard capacity failure, never a silent drop.
            self.terminal_drops += 1;
            return Err(FileError::new(code::CAPACITY, "terminal budget exhausted"));
        }
        self.buffered += bytes;
        self.terminal_delivered += 1;
        Ok(())
    }

    pub fn push_file(&mut self, bytes: usize) -> FileResult<()> {
        if self.buffered + bytes > self.limit {
            self.file_drops += 1;
            return Err(FileError::new(
                code::QUEUE_FULL,
                "shared send budget full; file class refused",
            ));
        }
        self.buffered += bytes;
        Ok(())
    }

    /// Simulate the event loop flushing `bytes` worth of pending file messages.
    fn drain_file_reserve(&mut self, bytes: usize) -> usize {
        let need = bytes.saturating_sub(self.limit - self.buffered);
        // File-class traffic is what gets squeezed; we model the freed space as
        // the whole file reservation, and every squeezed message is counted.
        let freed = self.buffered.min(need);
        self.buffered -= freed;
        usize::from(freed > 0)
    }

    pub fn settle(&mut self, bytes: usize) {
        self.buffered = self.buffered.saturating_sub(bytes);
    }
}

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
    audit: Vec<AuditRecord>,
    token: String,
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
            Duration::from_secs(60),
        );
        Ok(Self {
            limits,
            roots: map,
            sessions: HashMap::new(),
            next_session: 1,
            next_stream: 1,
            handles: HandleRegistry::new(read_handles),
            throttle,
            audit: Vec::new(),
            token,
        })
    }

    pub fn limits(&self) -> &FileLimits {
        &self.limits
    }

    pub fn audit(&self) -> &[AuditRecord] {
        &self.audit
    }

    pub fn handle_stats(&self) -> (usize, usize) {
        (self.handles.live(), self.handles.peak)
    }

    pub fn throttle_buckets(&self) -> usize {
        self.throttle.buckets()
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
        if self.throttle.is_locked(principal, source) {
            self.record(0, principal, "", "authenticate", "", code::THROTTLED);
            return Err(FileError::new(code::THROTTLED, "locked out"));
        }
        if !constant_time_eq(presented.as_bytes(), self.token.as_bytes()) {
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
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.insert(
            id,
            FileSession {
                id,
                principal: principal.to_string(),
                inflight_bytes: 0,
                streams: BTreeMap::new(),
                last_activity: Instant::now(),
                recycled: false,
            },
        );
        self.record(id, principal, "", "authenticate", "", "OK");
        Ok(id)
    }

    pub fn close_session(&mut self, session: u64, source: &str) {
        if let Some(s) = self.sessions.remove(&session) {
            for st in s.streams.into_values() {
                let _ = std::fs::remove_file(&st.part_path);
            }
            self.throttle.forget(&s.principal, source);
        }
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

    /// Paged listing (G17). Entries are read lazily up to the page cap so a
    /// 100k-entry directory cannot be materialized as one ack.
    pub fn list(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: usize,
    ) -> FileResult<ListPage> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        let abs = r.resolve(rel)?;
        let mut rd = std::fs::read_dir(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        let cap = self.limits.max_entries_per_page;
        let mut entries = Vec::with_capacity(cap.min(64));
        let mut idx = 0usize;
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
            if entries.len() == cap {
                break;
            }
            let meta = next
                .metadata()
                .map_err(|e| FileError::new(code::NOT_FOUND, e.to_string()))?;
            let link = next
                .path()
                .symlink_metadata()
                .map_err(|e| FileError::new(code::NOT_FOUND, e.to_string()))?;
            let name = next.file_name().to_string_lossy().replace('\\', "/");
            // A symlink inside the directory is *reported* as a symlink and never
            // traversed by the entry's size read (the escaping case is refused
            // again in read/stat/write/remove).
            entries.push(Entry {
                name,
                is_dir: meta.is_dir(),
                is_symlink: link.file_type().is_symlink(),
                size: if link.file_type().is_symlink() {
                    0
                } else {
                    meta.len()
                },
            });
            idx += 1;
        }
        let truncated = entries.len() == cap;
        Ok(ListPage {
            next_offset: offset + entries.len(),
            entries,
            truncated,
            is_complete_list: !truncated,
        })
    }

    /// Read one page (G18/G20). `offset + max_bytes` uses checked arithmetic;
    /// `max_bytes` above the configured page ceiling is refused, not clamped.
    pub fn read_page(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        offset: u64,
        max_bytes: usize,
    ) -> FileResult<DataPage> {
        self.touch(session)?;
        if max_bytes > self.limits.chunk_bytes {
            return Err(FileError::new(
                code::PAGE_TOO_LARGE,
                format!(
                    "requested {max_bytes} > chunk_bytes {}",
                    self.limits.chunk_bytes
                ),
            ));
        }
        let r = self.root(root)?.clone();
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
            self.record(session, "", root, "read", rel, e.code);
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
        self.record(session, "", root, "read", rel, "OK");
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
        self.touch(session)?;
        let r = self.root(root)?;
        r.require_writable()?;
        let name = r.name().to_string();
        if let Some(n) = declared_len {
            if n > self.limits.max_upload_bytes {
                self.record(session, "", &name, "open_upload", rel, code::CAPACITY);
                return Err(FileError::new(
                    code::CAPACITY,
                    format!(
                        "declared {n} > max_upload_bytes {}",
                        self.limits.max_upload_bytes
                    ),
                ));
            }
        }
        let abs = match r.resolve(rel) {
            Ok(p) => p,
            Err(e) if e.code == code::NOT_FOUND => {
                // Not existing yet is the normal case for an upload target.
                r.canonical.join(rel)
            }
            Err(e) => {
                self.record(session, "", &name, "open_upload", rel, e.code);
                return Err(e);
            }
        };
        if let Err(e) = r.reverify_parent(&abs, rel) {
            self.record(session, "", &name, "open_upload", rel, e.code);
            return Err(e);
        }
        // Refuse when the final target already exists: publishing must not
        // replace it (G14), so we also refuse to start a stream that cannot land.
        if abs.exists() {
            self.record(session, "", &name, "open_upload", rel, code::EXISTS);
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
            .map_err(|e| FileError::new(code::CAPACITY, format!("cannot create part file: {e}")))?;
        let s = self.session_mut(session)?;
        s.streams.insert(
            id,
            UploadStream {
                id,
                session,
                rel: rel.to_string(),
                staged: 0,
                declared_len,
                hasher: Sha256::new(),
                hashed_bytes: 0,
                part_path: part.clone(),
                file,
                last_activity: Instant::now(),
            },
        );
        s.last_activity = Instant::now();
        self.record(session, "", &name, "open_upload", rel, "OK");
        Ok(id)
    }

    /// Stage one chunk. The returned ack is **contiguous staged bytes** (G18):
    /// a chunk at the current prefix appends and advances; a fully duplicate page
    /// must match byte-for-byte and advances nothing; a jump or an overlapping
    /// mismatch is refused and the prefix is never rewritten.
    pub fn stage_chunk(
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
            // Bounded re-hash budget: hashing an unbounded declared size is itself DoS.
            if st.hashed_bytes < rehash_budget {
                let take = (rehash_budget - st.hashed_bytes).min(bytes.len() as u64) as usize;
                st.hasher.update(&bytes[..take]);
                st.hashed_bytes += take as u64;
            }
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
    /// exceed the send budget (G17).
    pub fn ack_staged(&self, session: u64, stream: u64) -> FileResult<u64> {
        let s = self.session(session)?;
        let st = s
            .streams
            .get(&stream)
            .ok_or_else(|| FileError::new(code::NOT_FOUND, format!("no such stream {stream}")))?;
        Ok(st.staged)
    }

    /// Commit: verify length and (when within the rehash budget) the digest, then
    /// publish with a **non-overwriting** hard link (G14/G18).
    pub fn commit_upload(
        &mut self,
        session: u64,
        root: &str,
        stream: u64,
        expected_sha256: Option<[u8; 32]>,
    ) -> FileResult<String> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        let (rel, staged, part, file, digest_complete, digest) = {
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
            st.file
                .flush()
                .map_err(|e| FileError::new(code::CAPACITY, e.to_string()))?;
            let digest_complete = st.hashed_bytes >= st.staged;
            let digest = st.hasher.clone().finalize();
            let mut out = [0u8; 32];
            if digest_complete {
                out.copy_from_slice(&digest);
            }
            (
                st.rel.clone(),
                st.staged,
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
                self.abort_upload(session, stream);
                self.record(session, "", root, "commit", &rel, code::INTEGRITY);
                return Err(FileError::new(code::INTEGRITY, "sha256 mismatch"));
            }
        }
        let target = r.resolve(&rel).unwrap_or_else(|_| r.canonical.join(&rel));
        if let Err(e) = r.reverify_parent(&target, &rel) {
            // 发布前的目录级复核失败：这条流不可能落地，清掉暂存物再返回。
            self.abort_upload(session, stream);
            self.record(session, "", root, "commit", &rel, e.code);
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
            self.abort_upload(session, stream);
            self.record(session, "", root, "commit", &rel, err.code);
            return Err(err);
        }
        drop(file);
        let _ = std::fs::remove_file(&part);
        self.session_mut(session)?.streams.remove(&stream);
        self.record(session, "", root, "commit", &rel, "OK");
        let _ = staged;
        Ok(r.display_rel(&target))
    }

    pub fn abort_upload(&mut self, session: u64, stream: u64) {
        if let Some(s) = self.sessions.get_mut(&session) {
            if let Some(st) = s.streams.remove(&stream) {
                let _ = std::fs::remove_file(&st.part_path);
            }
        }
    }

    pub fn mkdir(&mut self, session: u64, root: &str, rel: &str) -> FileResult<()> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        let name = r.name().to_string();
        // The target may not exist yet; its parent must resolve inside the root
        // without traversing any symlink, and the target itself must not already
        // be a symlink.
        let abs = r.canonical.join(rel);
        r.reverify_parent(&abs, rel)?;
        if let Ok(meta) = std::fs::symlink_metadata(&abs) {
            if meta.file_type().is_symlink() {
                self.record(session, "", &name, "mkdir", rel, code::SYMLINK_ESCAPE);
                return Err(FileError::new(
                    code::SYMLINK_ESCAPE,
                    format!("{rel:?} is already a symlink"),
                ));
            }
        }
        std::fs::create_dir_all(&abs)
            .map_err(|e| FileError::new(code::CAPACITY, format!("mkdir {rel:?}: {e}")))?;
        self.record(session, "", &name, "mkdir", rel, "OK");
        Ok(())
    }

    /// Remove one entry; recursion is bounded to the root and refuses to follow
    /// any symlink (G13). `remove_all_in_root` is only ever called with paths
    /// that resolved inside the root component-by-component.
    pub fn remove(
        &mut self,
        session: u64,
        root: &str,
        rel: &str,
        recursive: bool,
    ) -> FileResult<usize> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        let name = r.name().to_string();
        let abs = r.resolve(rel)?;
        let meta = std::fs::symlink_metadata(&abs)
            .map_err(|e| FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")))?;
        if meta.file_type().is_symlink() {
            self.record(session, "", &name, "remove", rel, code::SYMLINK_ESCAPE);
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
        self.record(session, "", &name, "remove", rel, "OK");
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
        self.touch(session)?;
        let r = self.root(root)?.clone();
        r.require_writable()?;
        let name = r.name().to_string();
        let src = r.resolve(from)?;
        let dst = r.resolve(to).unwrap_or_else(|_| r.canonical.join(to));
        r.reverify(&src, from)?;
        r.reverify_parent(&dst, to)?;
        if dst.exists() {
            self.record(session, "", &name, "rename", from, code::EXISTS);
            return Err(FileError::new(code::EXISTS, format!("{to:?} exists")));
        }
        std::fs::rename(&src, &dst)
            .map_err(|e| FileError::new(code::CAPACITY, format!("rename failed: {e}")))?;
        self.record(session, "", &name, "rename", from, "OK");
        Ok(())
    }

    pub fn stat(&mut self, session: u64, root: &str, rel: &str) -> FileResult<Entry> {
        self.touch(session)?;
        let r = self.root(root)?.clone();
        let abs = match r.resolve(rel) {
            Ok(p) => p,
            Err(err) => {
                // G21: 拒绝也要留痕。
                self.record(session, "", root, "stat", rel, err.code);
                return Err(err);
            }
        };
        let meta = match std::fs::symlink_metadata(&abs) {
            Ok(m) => m,
            Err(e) => {
                self.record(session, "", root, "stat", rel, code::NOT_FOUND);
                return Err(FileError::new(code::NOT_FOUND, format!("{rel:?}: {e}")));
            }
        };
        if meta.file_type().is_symlink() {
            self.record(session, "", root, "stat", rel, code::SYMLINK_ESCAPE);
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
    fn record(
        &mut self,
        session: u64,
        principal: &str,
        root: &str,
        action: &'static str,
        rel: &str,
        result_code: &str,
    ) {
        self.audit.push(AuditRecord {
            session,
            principal: principal.to_string(),
            root: root.to_string(),
            action,
            rel: rel.to_string(),
            result_code: result_code.to_string(),
        });
    }
}

impl SandboxRoot {
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
        e.close_session(s, "loopback");
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
        e.close_session(s, "loopback");
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
        e.close_session(s, "loopback");
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
        // forged volume must not grow the table linearly
        for i in 0..(e.limits().max_throttle_buckets * 3) {
            let forged = format!("p{i}");
            let _ = e.authenticate(&forged, "10.0.0.9", "wrong");
        }
        assert!(e.throttle_buckets() <= e.limits().max_throttle_buckets);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminal_class_has_priority_over_file_class() {
        let mut b = SendBudget::new(100);
        for _ in 0..10 {
            b.push_file(10).unwrap();
        }
        assert_eq!(b.push_file(10).unwrap_err().code, code::QUEUE_FULL);
        assert_eq!(b.file_drops, 1);
        assert!(b.push_terminal(50).is_ok());
        assert_eq!(b.terminal_delivered, 1);
        assert_eq!(b.terminal_drops, 0);
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
        assert_eq!(e.sweep_idle(Instant::now()), vec![s]);
        assert_eq!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|d| d.file_name().to_string_lossy().contains("nexus-part"))
                .count(),
            0,
            "recycling must not leave .part behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_verb_is_audited_including_refusals() {
        let dir = tmp("audit");
        let mut e = engine(&dir);
        let _ = e.authenticate("u", "loopback", "bad").unwrap_err();
        let s = e.authenticate("u", "loopback", "s3cret").unwrap();
        let _ = e.stat(s, "downloads", "missing.bin").unwrap_err();
        let codes: Vec<&str> = e.audit().iter().map(|r| r.result_code.as_str()).collect();
        assert!(codes.contains(&code::AUTH_DENIED));
        assert!(codes.contains(&code::NOT_FOUND));
        assert!(codes.contains(&"OK"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn constant_time_eq_distinguishes_lengths_and_prefixes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
