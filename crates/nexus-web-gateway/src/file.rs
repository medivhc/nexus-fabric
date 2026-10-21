//! File access and upload engine (REQ-005..REQ-008).
//!
//! A file session is driven exactly like an SSH terminal bridge: one worker
//! thread owns the backend handle, the event loop sends [`FileCommand`]s over an
//! `mpsc` channel, and results come back through the gateway event channel. The
//! crate stays std-only (no async runtime).
//!
//! Two interchangeable backends implement [`FileBackend`]:
//!
//! * [`SftpBackend`] — the node's SSH client (libssh2) authenticates to the
//!   target sshd with the browser's in-memory credentials and runs the SFTP
//!   subsystem. The gateway node exposes no filesystem of its own, and every
//!   path is resolved against the remote account's home (the SFTP server's
//!   working directory).
//! * [`LocalSandbox`] — an explicitly configured node-local directory
//!   (`files.roots`). Paths are canonicalized against the root, so neither `..`
//!   nor a symlink inside the root reaches outside it (G13).
//!
//! Bulk bytes never travel as JSON: the control DataChannel carries the small
//! `file_*` messages, while chunks move over a separate **binary** DataChannel
//! (label [`FILE_CHANNEL_LABEL`]) with a fixed 14-byte header. Reads are
//! pull-based (`file_read{offset,len}` → one chunk), which paces the transfer
//! and makes resuming trivial. Uploads are acknowledged with the number of
//! *contiguous* bytes staged, and commit from a `.part` file via rename (G14),
//! so a browser that dies mid-upload leaves no half-written file behind.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::config::{FileConfig, FileRoot};
use crate::protocol::{FileEntry, SshAuth};
use crate::ssh_client;

/// Label of the binary DataChannel that carries file chunks.
pub const FILE_CHANNEL_LABEL: &str = "nexus.file";

/// Frame kind: chunk of file data flowing node → browser.
pub const FRAME_READ_CHUNK: u8 = 0x01;
/// Frame kind: chunk of file data flowing browser → node.
pub const FRAME_WRITE_CHUNK: u8 = 0x81;

/// Frame header: `kind(1) | stream_id(4, BE) | offset(8, BE) | flags(1)`.
pub const FRAME_HEADER_LEN: usize = 14;

/// Frame flag: this chunk is the last one for the stream.
pub const FRAME_FLAG_FINAL: u8 = 0x01;

/// Suffix of the staging file an upload writes into before its rename.
pub const PART_SUFFIX: &str = "nexus-part";

/// Error used when the backend never came up.
const SESSION_UNAVAILABLE: &str = "file session not open";

/// TCP connect + SSH handshake timeout for the SFTP backend.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Resource limits taken from [`FileConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileLimits {
    /// Maximum chunk payload the backend reads or accepts per frame.
    pub chunk_bytes: usize,
    /// Maximum accepted upload size per stream.
    pub max_upload_bytes: u64,
}

impl From<&FileConfig> for FileLimits {
    fn from(cfg: &FileConfig) -> Self {
        Self {
            chunk_bytes: cfg.chunk_bytes.max(1),
            max_upload_bytes: cfg.max_upload_bytes,
        }
    }
}

/// A decoded binary file frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// [`FRAME_READ_CHUNK`] or [`FRAME_WRITE_CHUNK`].
    pub kind: u8,
    /// Stream this chunk belongs to (assigned by the browser).
    pub stream_id: u32,
    /// Absolute byte offset of `data` within the file.
    pub offset: u64,
    /// Last chunk of the stream.
    pub final_block: bool,
    /// The file bytes themselves.
    pub data: &'a [u8],
}

/// Encode a binary file frame for the file DataChannel.
pub fn encode_frame(
    kind: u8,
    stream_id: u32,
    offset: u64,
    final_block: bool,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + data.len());
    out.push(kind);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.push(if final_block { FRAME_FLAG_FINAL } else { 0 });
    out.extend_from_slice(data);
    out
}

/// Decode a binary file frame.
///
/// # Errors
///
/// Returns a description when the buffer is shorter than the header or carries
/// an unknown frame kind. Errors stay plain strings because the caller renders
/// them into a `file_op_ack` or a log line, never a panic.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, String> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(format!(
            "frame too short: {} bytes, need {FRAME_HEADER_LEN}",
            bytes.len()
        ));
    }
    let kind = bytes[0];
    if kind != FRAME_READ_CHUNK && kind != FRAME_WRITE_CHUNK {
        return Err(format!("unknown file frame kind {kind:#04x}"));
    }
    let stream_id = u32::from_be_bytes(bytes[1..5].try_into().expect("checked length"));
    let offset = u64::from_be_bytes(bytes[5..13].try_into().expect("checked length"));
    let flags = bytes[13];
    Ok(Frame {
        kind,
        stream_id,
        offset,
        final_block: flags & FRAME_FLAG_FINAL != 0,
        data: &bytes[FRAME_HEADER_LEN..],
    })
}

/// Normalize a root-relative path.
///
/// G13: the browser may only address paths *inside* the session root. `/` is
/// the root; `.` and empty components are dropped; a `..` component or a NUL is
/// rejected outright (no normalization games), and `\` is not accepted as a
/// separator so Windows-style traversal cannot smuggle a path out.
///
/// # Errors
///
/// Returns a description when the path contains `..`, `\`, or a NUL byte.
pub fn normalize_rel(path: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    for raw in path.split('/') {
        match raw {
            "" | "." => continue,
            ".." => return Err("path traversal ('..') is not allowed".into()),
            component => {
                if component.contains('\0') {
                    return Err("NUL byte in path".into());
                }
                if component.contains('\\') {
                    return Err("backslash is not a path separator".into());
                }
                parts.push(component.to_string());
            }
        }
    }
    Ok(parts)
}

/// Render normalized components back into a `/`-prefixed relative path.
pub fn render_rel(parts: &[String]) -> String {
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Children of a directory listing that must never be surfaced.
fn is_dot_name(name: &str) -> bool {
    name == "." || name == ".."
}

/// Last component of a listing entry name.
///
/// libssh2's `readdir` echoes the queried directory as a path prefix
/// (`sub/remote.txt`), while the entry's own name is only the tail.
fn base_name(raw: &str) -> String {
    raw.rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(raw)
        .to_string()
}

/// Resolve a relative path inside `root`, following symlinks but refusing any
/// result outside it. Paths that do not exist yet are checked through their
/// deepest existing ancestor, so a symlinked directory cannot leak either.
fn resolve_within(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let parts = normalize_rel(rel)?;
    let root_real = root
        .canonicalize()
        .map_err(|e| format!("root {} unavailable: {e}", root.display()))?;
    let mut joined = root_real.clone();
    for part in &parts {
        joined.push(part);
    }
    let real = deepest_resolved(&joined, &root_real)?;
    if !real.starts_with(&root_real) {
        return Err(format!("path escapes root: {rel}"));
    }
    Ok(real)
}

/// Canonicalize the deepest existing ancestor of `target`, then re-join the
/// remaining component names.
fn deepest_resolved(target: &Path, boundary: &Path) -> Result<PathBuf, String> {
    let mut cursor = target.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = cursor.canonicalize() {
            let mut out = real;
            for name in tail.iter().rev() {
                out.push(name);
            }
            return Ok(out);
        }
        if cursor == boundary {
            return Ok(cursor);
        }
        let name = cursor
            .file_name()
            .ok_or_else(|| "path has no ancestors to resolve".to_string())?
            .to_os_string();
        tail.push(name);
        cursor = cursor
            .parent()
            .ok_or_else(|| "path has no parent".to_string())?
            .to_path_buf();
    }
}

/// The directory entries a backend reports.
type Entries = Vec<FileEntry>;

/// Operations both backends provide. Each takes `&mut self` because an engine
/// owns its protocol handles. Every `Err` is a browser-safe description.
pub trait FileBackend: Send {
    /// `sftp` or `local`; echoed in `file_open_ack`.
    fn kind(&self) -> &'static str;

    /// List a directory (`""` or `"/"` is the session root).
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn list(&mut self, path: &str) -> Result<Entries, String>;

    /// Stat one entry.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn stat(&mut self, path: &str) -> Result<FileEntry, String>;

    /// Read up to `len` bytes at `offset`; the second element is `true` at EOF.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn read_at(
        &mut self,
        stream_id: u32,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, bool), String>;

    /// Create (or truncate) the staging file an upload writes into.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn part_open(&mut self, stream_id: u32, path: &str) -> Result<(), String>;

    /// Append contiguous bytes to the staging file.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn part_append(&mut self, stream_id: u32, data: &[u8]) -> Result<(), String>;

    /// Move the staging file onto its final path (G14).
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn part_commit(&mut self, stream_id: u32) -> Result<(), String>;

    /// Discard the staging file of a failed or abandoned upload.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn part_abort(&mut self, stream_id: u32) -> Result<(), String>;

    /// Create a directory.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn mkdir(&mut self, path: &str) -> Result<(), String>;

    /// Remove a file, or a directory when `recursive`.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn remove(&mut self, path: &str, recursive: bool) -> Result<(), String>;

    /// Rename within the session root; an existing target is refused.
    ///
    /// # Errors
    ///
    /// Backend-specific description on failure.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), String>;

    /// Release every handle the backend holds (worker shutdown).
    fn release(&mut self) {}
}

/// Sort entries directories-first, then case-insensitively by name.
fn sort_entries(entries: &mut Entries) {
    entries.sort_by(|a, b| {
        (a.kind != "dir", a.name.to_lowercase()).cmp(&(b.kind != "dir", b.name.to_lowercase()))
    });
}

/// A cached read handle, reused while the browser pulls a file sequentially.
struct ReadHandle<P> {
    target: P,
    file: fs::File,
    pos: u64,
}

/// A node-local directory exposed to file sessions (REQ-008).
pub struct LocalSandbox {
    root: PathBuf,
    read_only: bool,
    limits: FileLimits,
    reads: HashMap<u32, ReadHandle<PathBuf>>,
    parts: HashMap<u32, LocalPart>,
}

struct LocalPart {
    file: fs::File,
    part_path: PathBuf,
    final_path: PathBuf,
}

impl LocalSandbox {
    /// Build a sandbox for one configured root.
    ///
    /// # Errors
    ///
    /// Returns a description when the configured path is missing or is not a
    /// directory.
    pub fn new(root: &FileRoot, limits: FileLimits) -> Result<Self, String> {
        let path = Path::new(&root.path);
        if !path.is_dir() {
            return Err(format!("root {} is not an existing directory", root.name));
        }
        Ok(Self {
            root: path.to_path_buf(),
            read_only: root.read_only,
            limits,
            reads: HashMap::new(),
            parts: HashMap::new(),
        })
    }

    fn writable(&self) -> Result<(), String> {
        if self.read_only {
            return Err("root is read-only".into());
        }
        Ok(())
    }

    fn resolve(&self, rel: &str) -> Result<PathBuf, String> {
        resolve_within(&self.root, rel)
    }

    fn entry_at(&self, name: String, abs: &Path) -> FileEntry {
        let path = abs
            .strip_prefix(&self.root)
            .map(|p| {
                render_rel(
                    &p.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_else(|_| format!("/{name}"));
        let (size, mtime, mode, kind) = match fs::symlink_metadata(abs) {
            Ok(md) => {
                let ft = md.file_type();
                let kind = if ft.is_dir() {
                    "dir"
                } else if ft.is_symlink() {
                    "symlink"
                } else if ft.is_file() {
                    "file"
                } else {
                    "other"
                };
                (
                    if ft.is_dir() { 0 } else { md.len() },
                    md.modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    mode_of(&md),
                    kind.to_string(),
                )
            }
            Err(_) => (0, 0, 0, "other".to_string()),
        };
        FileEntry {
            name,
            path,
            kind,
            size,
            mtime,
            mode,
        }
    }
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_md: &fs::Metadata) -> u32 {
    0
}

impl FileBackend for LocalSandbox {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn list(&mut self, path: &str) -> Result<Entries, String> {
        let dir = self.resolve(path)?;
        let mut out = Entries::new();
        for item in fs::read_dir(&dir).map_err(|e| format!("list {path}: {e}"))? {
            let item = item.map_err(|e| format!("list {path}: {e}"))?;
            out.push(self.entry_at(
                item.file_name().to_string_lossy().into_owned(),
                &item.path(),
            ));
        }
        sort_entries(&mut out);
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<FileEntry, String> {
        let abs = self.resolve(path)?;
        let name = abs
            .file_name()
            .ok_or_else(|| "cannot stat the session root".to_string())?
            .to_string_lossy()
            .into_owned();
        if abs.symlink_metadata().is_err() {
            return Err(format!("{path}: not found"));
        }
        Ok(self.entry_at(name, &abs))
    }

    fn read_at(
        &mut self,
        stream_id: u32,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, bool), String> {
        let want = len.clamp(1, self.limits.chunk_bytes.max(1));
        let abs = self.resolve(path)?;
        // Reopen when this stream points at a different file, or has no handle.
        let needs_open = match self.reads.get(&stream_id) {
            Some(handle) => handle.target != abs,
            None => true,
        };
        if needs_open {
            let file = fs::File::open(&abs).map_err(|e| format!("open {path}: {e}"))?;
            self.reads.insert(
                stream_id,
                ReadHandle {
                    target: abs.clone(),
                    file,
                    pos: 0,
                },
            );
        }
        let handle = self
            .reads
            .get_mut(&stream_id)
            .expect("handle inserted above");
        if handle.pos != offset {
            handle.pos = handle
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| format!("seek {path}: {e}"))?;
        }
        let mut buf = vec![0u8; want];
        let mut read = 0usize;
        let mut eof = false;
        while read < want {
            match handle.file.read(&mut buf[read..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read {path}: {e}")),
            }
        }
        buf.truncate(read);
        handle.pos += read as u64;
        let empty = buf.is_empty();
        Ok((buf, eof || empty))
    }

    fn part_open(&mut self, stream_id: u32, path: &str) -> Result<(), String> {
        self.writable()?;
        let parts = normalize_rel(path)?;
        if parts.is_empty() {
            return Err("upload target must be a file path".into());
        }
        let final_path = self.resolve(path)?;
        let parent = final_path
            .parent()
            .ok_or_else(|| "upload needs a parent directory".to_string())?;
        if !parent.is_dir() {
            return Err(format!("target directory for {path} does not exist"));
        }
        if final_path.is_dir() {
            return Err(format!("{path} is a directory"));
        }
        let name = final_path
            .file_name()
            .ok_or_else(|| "upload target has no file name".to_string())?
            .to_string_lossy()
            .into_owned();
        let part_path = parent.join(format!(".{stream_id}.{name}.{PART_SUFFIX}"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)
            .map_err(|e| format!("create staging file: {e}"))?;
        self.parts.insert(
            stream_id,
            LocalPart {
                file,
                part_path,
                final_path,
            },
        );
        Ok(())
    }

    fn part_append(&mut self, stream_id: u32, data: &[u8]) -> Result<(), String> {
        self.writable()?;
        let part = self
            .parts
            .get_mut(&stream_id)
            .ok_or("no upload for stream")?;
        part.file
            .write_all(data)
            .map_err(|e| format!("write staging file: {e}"))?;
        part.file
            .flush()
            .map_err(|e| format!("flush staging file: {e}"))
    }

    fn part_commit(&mut self, stream_id: u32) -> Result<(), String> {
        self.writable()?;
        let part = self
            .parts
            .remove(&stream_id)
            .ok_or("no upload for stream")?;
        drop(part.file);
        fs::rename(&part.part_path, &part.final_path).map_err(|e| format!("commit upload: {e}"))?;
        Ok(())
    }

    fn part_abort(&mut self, stream_id: u32) -> Result<(), String> {
        if let Some(part) = self.parts.remove(&stream_id) {
            drop(part.file);
            let _ = fs::remove_file(&part.part_path);
        }
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<(), String> {
        self.writable()?;
        if normalize_rel(path)?.is_empty() {
            return Err("cannot mkdir the session root".into());
        }
        let abs = self.resolve(path)?;
        fs::create_dir_all(&abs).map_err(|e| format!("mkdir {path}: {e}"))
    }

    fn remove(&mut self, path: &str, recursive: bool) -> Result<(), String> {
        self.writable()?;
        if normalize_rel(path)?.is_empty() {
            return Err("refusing to remove the session root".into());
        }
        let abs = self.resolve(path)?;
        let md = abs
            .symlink_metadata()
            .map_err(|e| format!("stat {path}: {e}"))?;
        if md.is_dir() {
            if recursive {
                fs::remove_dir_all(&abs).map_err(|e| format!("rmdir -r {path}: {e}"))
            } else {
                fs::remove_dir(&abs).map_err(|e| format!("rmdir {path}: {e}"))
            }
        } else {
            fs::remove_file(&abs).map_err(|e| format!("rm {path}: {e}"))
        }
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        self.writable()?;
        if normalize_rel(from)?.is_empty() || normalize_rel(to)?.is_empty() {
            return Err("cannot rename the session root".into());
        }
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        if dst.symlink_metadata().is_ok() {
            return Err(format!("rename target already exists: {to}"));
        }
        fs::rename(&src, &dst).map_err(|e| format!("rename {from} -> {to}: {e}"))
    }

    fn release(&mut self) {
        let streams: Vec<u32> = self.parts.keys().copied().collect();
        for stream_id in streams {
            let _ = self.part_abort(stream_id);
        }
        self.reads.clear();
    }
}

/// SFTP over the node-side SSH client (REQ-005).
///
/// Runs on its own TCP connection and SSH session, separate from any terminal:
/// a pty channel and a bulk transfer must not interfere, and the credentials
/// stay in memory exactly as G4 requires.
pub struct SftpBackend {
    #[allow(dead_code)]
    session: ssh2::Session,
    sftp: ssh2::Sftp,
    limits: FileLimits,
    reads: HashMap<u32, SftpRead>,
    parts: HashMap<u32, SftpPart>,
}

struct SftpRead {
    path: String,
    file: ssh2::File,
    pos: u64,
}

struct SftpPart {
    part_path: String,
    final_path: String,
    file: ssh2::File,
}

impl SftpBackend {
    /// Connect, authenticate, and open the SFTP subsystem.
    ///
    /// # Errors
    ///
    /// Returns a description when the TCP connect, SSH handshake,
    /// authentication, or subsystem open fails.
    pub fn connect(
        target: SocketAddr,
        auth: Option<SshAuth>,
        limits: FileLimits,
    ) -> Result<Self, String> {
        let tcp = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
            .map_err(|e| format!("connect to {target}: {e}"))?;
        let _ = tcp.set_nodelay(true);
        let mut session = ssh2::Session::new().map_err(|e| format!("ssh session: {e}"))?;
        session.set_tcp_stream(tcp);
        session.set_timeout(CONNECT_TIMEOUT.as_millis() as u32);
        session
            .handshake()
            .map_err(|e| format!("ssh handshake: {e}"))?;
        ssh_client::authenticate(&session, auth)?;
        if !session.authenticated() {
            return Err("authentication failed: not authenticated".into());
        }
        let sftp = session
            .sftp()
            .map_err(|e| format!("open sftp subsystem: {e}"))?;
        Ok(Self {
            session,
            sftp,
            limits,
            reads: HashMap::new(),
            parts: HashMap::new(),
        })
    }

    /// Map a session-relative path onto the remote side.
    ///
    /// The session root is the remote account's home directory (the SFTP
    /// server's working directory), so relative paths are what keeps the browser
    /// inside it; `.` asks for the home itself.
    fn remote_path(&self, rel: &str) -> Result<String, String> {
        let parts = normalize_rel(rel)?;
        Ok(if parts.is_empty() {
            ".".to_string()
        } else {
            parts.join("/")
        })
    }

    fn to_entry(name: String, path: String, stat: &ssh2::FileStat) -> FileEntry {
        let ft = stat.file_type();
        let kind = if ft.is_dir() {
            "dir"
        } else if ft.is_symlink() {
            "symlink"
        } else {
            "file"
        };
        FileEntry {
            name,
            path,
            kind: kind.to_string(),
            size: if ft.is_dir() {
                0
            } else {
                stat.size.unwrap_or(0)
            },
            mtime: stat.mtime.unwrap_or(0) as i64,
            // libssh2 reports the full st_mode (type bits included); the browser
            // only wants the permission triplets, matching the local backend.
            mode: stat.perm.unwrap_or(0) & 0o7777,
        }
    }
}

impl FileBackend for SftpBackend {
    fn kind(&self) -> &'static str {
        "sftp"
    }

    fn list(&mut self, path: &str) -> Result<Entries, String> {
        let dir = self.remote_path(path)?;
        let prefix = normalize_rel(path)?;
        let listing = self
            .sftp
            .readdir(&dir)
            .map_err(|e| format!("list {path}: {e}"))?;
        let mut out = Entries::new();
        for (name, stat) in listing {
            let base = base_name(&name.to_string_lossy());
            if is_dot_name(&base) {
                continue;
            }
            let mut parts = prefix.clone();
            parts.push(base.clone());
            out.push(SftpBackend::to_entry(base, render_rel(&parts), &stat));
        }
        sort_entries(&mut out);
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<FileEntry, String> {
        let remote = self.remote_path(path)?;
        let stat = self
            .sftp
            .stat(Path::new(&remote))
            .map_err(|e| format!("stat {path}: {e}"))?;
        let parts = normalize_rel(path)?;
        let name = parts.last().cloned().unwrap_or_else(|| "/".into());
        Ok(SftpBackend::to_entry(name, render_rel(&parts), &stat))
    }

    fn read_at(
        &mut self,
        stream_id: u32,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, bool), String> {
        let want = len.clamp(1, self.limits.chunk_bytes.max(1));
        let remote = self.remote_path(path)?;
        let needs_open = match self.reads.get(&stream_id) {
            Some(handle) => handle.path != remote,
            None => true,
        };
        if needs_open {
            let file = self
                .sftp
                .open_mode(&remote, ssh2::OpenFlags::READ, 0o644, ssh2::OpenType::File)
                .map_err(|e| format!("open {path}: {e}"))?;
            self.reads.insert(
                stream_id,
                SftpRead {
                    path: remote,
                    file,
                    pos: 0,
                },
            );
        }
        let handle = self
            .reads
            .get_mut(&stream_id)
            .expect("handle inserted above");
        if handle.pos != offset {
            handle.pos = handle
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| format!("seek {path}: {e}"))?;
        }
        let mut buf = vec![0u8; want];
        let mut read = 0usize;
        let mut eof = false;
        while read < want {
            match handle.file.read(&mut buf[read..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read {path}: {e}")),
            }
        }
        buf.truncate(read);
        handle.pos += read as u64;
        let empty = buf.is_empty();
        Ok((buf, eof || empty))
    }

    fn part_open(&mut self, stream_id: u32, path: &str) -> Result<(), String> {
        let parts = normalize_rel(path)?;
        if parts.is_empty() {
            return Err("upload target must be a file path".into());
        }
        let final_path = self.remote_path(path)?;
        let part_path = format!("{final_path}.{PART_SUFFIX}");
        let file = match self.sftp.open_mode(
            &part_path,
            ssh2::OpenFlags::WRITE | ssh2::OpenFlags::TRUNCATE,
            0o644,
            ssh2::OpenType::File,
        ) {
            Ok(file) => file,
            Err(e) => return Err(format!("create staging file: {e}")),
        };
        self.parts.insert(
            stream_id,
            SftpPart {
                part_path,
                final_path,
                file,
            },
        );
        Ok(())
    }

    fn part_append(&mut self, stream_id: u32, data: &[u8]) -> Result<(), String> {
        let part = self
            .parts
            .get_mut(&stream_id)
            .ok_or("no upload for stream")?;
        part.file
            .write_all(data)
            .map_err(|e| format!("write staging file: {e}"))
    }

    fn part_commit(&mut self, stream_id: u32) -> Result<(), String> {
        let mut part = self
            .parts
            .remove(&stream_id)
            .ok_or("no upload for stream")?;
        let _ = part.file.flush();
        drop(part.file);
        self.sftp
            .rename(
                Path::new(&part.part_path),
                Path::new(&part.final_path),
                None,
            )
            .map_err(|e| format!("commit upload: {e}"))
    }

    fn part_abort(&mut self, stream_id: u32) -> Result<(), String> {
        if let Some(part) = self.parts.remove(&stream_id) {
            drop(part.file);
            let _ = self.sftp.unlink(Path::new(&part.part_path));
        }
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<(), String> {
        if normalize_rel(path)?.is_empty() {
            return Err("cannot mkdir the session root".into());
        }
        let remote = self.remote_path(path)?;
        self.sftp
            .mkdir(Path::new(&remote), 0o755)
            .map_err(|e| format!("mkdir {path}: {e}"))
    }

    fn remove(&mut self, path: &str, recursive: bool) -> Result<(), String> {
        if normalize_rel(path)?.is_empty() {
            return Err("refusing to remove the session root".into());
        }
        let remote = self.remote_path(path)?;
        let stat = self
            .sftp
            .stat(Path::new(&remote))
            .map_err(|e| format!("stat {path}: {e}"))?;
        if !stat.file_type().is_dir() {
            return self
                .sftp
                .unlink(Path::new(&remote))
                .map_err(|e| format!("rm {path}: {e}"));
        }
        if !recursive {
            return self
                .sftp
                .rmdir(Path::new(&remote))
                .map_err(|e| format!("rmdir {path}: {e}"));
        }
        // Depth first: children, then the directory itself.
        let children = self
            .sftp
            .readdir(Path::new(&remote))
            .map_err(|e| format!("list {path}: {e}"))?;
        let prefix = normalize_rel(path)?;
        for (name, child_stat) in children {
            let name = base_name(&name.to_string_lossy());
            if is_dot_name(&name) {
                continue;
            }
            let mut parts = prefix.clone();
            parts.push(name.clone());
            let child_rel = render_rel(&parts);
            let child_remote = parts.join("/");
            if child_stat.file_type().is_dir() {
                self.remove(&child_rel, true)?;
            } else {
                self.sftp
                    .unlink(Path::new(&child_remote))
                    .map_err(|e| format!("rm {child_rel}: {e}"))?;
            }
        }
        self.sftp
            .rmdir(Path::new(&remote))
            .map_err(|e| format!("rmdir {path}: {e}"))
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        if normalize_rel(from)?.is_empty() || normalize_rel(to)?.is_empty() {
            return Err("cannot rename the session root".into());
        }
        let src = self.remote_path(from)?;
        let dst = self.remote_path(to)?;
        // No OVERWRITE flag: an existing target must fail, never be replaced.
        self.sftp
            .rename(
                Path::new(&src),
                Path::new(&dst),
                Some(ssh2::RenameFlags::ATOMIC | ssh2::RenameFlags::NATIVE),
            )
            .map_err(|e| format!("rename {from} -> {to}: {e}"))
    }

    fn release(&mut self) {
        let streams: Vec<u32> = self.parts.keys().copied().collect();
        for stream_id in streams {
            let _ = self.part_abort(stream_id);
        }
        self.reads.clear();
    }
}

/// Commands the gateway event loop sends to a file worker thread.
#[derive(Debug)]
pub enum FileCommand {
    /// List a directory.
    List { session_id: String, path: String },
    /// Stat one entry.
    Stat { session_id: String, path: String },
    /// Read a chunk.
    Read {
        session_id: String,
        stream_id: u32,
        path: String,
        offset: u64,
        len: u32,
    },
    /// Start an upload.
    WriteBegin {
        session_id: String,
        stream_id: u32,
        path: String,
    },
    /// A chunk of an upload, already de-framed from the binary channel.
    WriteChunk {
        session_id: String,
        stream_id: u32,
        offset: u64,
        data: Vec<u8>,
    },
    /// Commit an upload.
    WriteEnd {
        session_id: String,
        stream_id: u32,
        path: String,
    },
    /// Create a directory.
    Mkdir { session_id: String, path: String },
    /// Remove an entry.
    Remove {
        session_id: String,
        path: String,
        recursive: bool,
    },
    /// Rename an entry.
    Rename {
        session_id: String,
        from: String,
        to: String,
    },
    /// Close the session.
    Close { session_id: String, reason: String },
}

/// Results a file worker reports back to the gateway event loop.
#[derive(Debug)]
pub enum FileReply {
    /// The backend came up (or failed to); always the first reply.
    Opened {
        session_id: String,
        kind: String,
        error: Option<String>,
    },
    /// Directory listing.
    Listed {
        session_id: String,
        path: String,
        entries: Entries,
        error: Option<String>,
    },
    /// Single entry.
    Statted {
        session_id: String,
        entry: Option<FileEntry>,
        error: Option<String>,
    },
    /// Chunk answering a `Read`; goes out as a binary frame.
    ReadChunk {
        session_id: String,
        stream_id: u32,
        offset: u64,
        data: Vec<u8>,
        final_block: bool,
        error: Option<String>,
    },
    /// Upload progress: `received` contiguous bytes are durably staged.
    WriteAck {
        session_id: String,
        stream_id: u32,
        received: u64,
        error: Option<String>,
    },
    /// A metadata operation finished.
    OpDone {
        session_id: String,
        op: String,
        path: String,
        error: Option<String>,
    },
    /// The session is closed.
    Closed { session_id: String, reason: String },
}

/// One in-flight upload: contiguous bytes staged, plus out-of-order chunks.
pub struct Upload {
    /// Relative path the staging file will be committed to.
    pub path: String,
    /// Contiguous bytes already appended to the staging file.
    pub next_offset: u64,
    /// Chunks received ahead of `next_offset`, keyed by their offset.
    pub buffered: BTreeMap<u64, Vec<u8>>,
}

/// Drive one file session to completion on its worker thread.
///
/// `backend` is either a live engine or the reason the session could not be
/// opened. A failed session still answers every command with an explicit error
/// (never silently, mirroring G9) until it is closed.
pub fn run_file_worker(
    backend: Result<Box<dyn FileBackend>, String>,
    session_id: String,
    rx: Receiver<FileCommand>,
    stop: Arc<AtomicBool>,
    limits: FileLimits,
    mut reply: impl FnMut(FileReply) + Send,
) {
    let mut backend: Option<Box<dyn FileBackend>> = match backend {
        Ok(engine) => {
            let kind = engine.kind().to_string();
            reply(FileReply::Opened {
                session_id: session_id.clone(),
                kind,
                error: None,
            });
            Some(engine)
        }
        Err(reason) => {
            reply(FileReply::Opened {
                session_id: session_id.clone(),
                kind: String::new(),
                error: Some(reason),
            });
            None
        }
    };
    let mut uploads: HashMap<u32, Upload> = HashMap::new();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let cmd = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(cmd) => cmd,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(engine) = backend.as_mut() {
                    engine.release();
                }
                reply(FileReply::Closed {
                    session_id: session_id.clone(),
                    reason: "upstream gone".into(),
                });
                return;
            }
        };

        match cmd {
            FileCommand::Close { session_id, reason } => {
                uploads.clear();
                if let Some(engine) = backend.as_mut() {
                    engine.release();
                }
                reply(FileReply::Closed { session_id, reason });
                return;
            }
            FileCommand::List { session_id, path } => {
                let (entries, error) = match backend.as_mut() {
                    Some(engine) => match engine.list(&path) {
                        Ok(entries) => (entries, None),
                        Err(e) => (Vec::new(), Some(e)),
                    },
                    None => (Vec::new(), Some(SESSION_UNAVAILABLE.to_string())),
                };
                reply(FileReply::Listed {
                    session_id,
                    path,
                    entries,
                    error,
                });
            }
            FileCommand::Stat { session_id, path } => {
                let (entry, error) = match backend.as_mut() {
                    Some(engine) => match engine.stat(&path) {
                        Ok(entry) => (Some(entry), None),
                        Err(e) => (None, Some(e)),
                    },
                    None => (None, Some(SESSION_UNAVAILABLE.to_string())),
                };
                reply(FileReply::Statted {
                    session_id,
                    entry,
                    error,
                });
            }
            FileCommand::Read {
                session_id,
                stream_id,
                path,
                offset,
                len,
            } => {
                let want = (len as usize).clamp(1, limits.chunk_bytes.max(1));
                let result = match backend.as_mut() {
                    Some(engine) => engine.read_at(stream_id, &path, offset, want),
                    None => Err(SESSION_UNAVAILABLE.to_string()),
                };
                match result {
                    Ok((data, final_block)) => reply(FileReply::ReadChunk {
                        session_id,
                        stream_id,
                        offset,
                        data,
                        final_block,
                        error: None,
                    }),
                    Err(e) => reply(FileReply::ReadChunk {
                        session_id,
                        stream_id,
                        offset,
                        data: Vec::new(),
                        final_block: true,
                        error: Some(e),
                    }),
                }
            }
            FileCommand::WriteBegin {
                session_id,
                stream_id,
                path,
            } => {
                let opened = match backend.as_mut() {
                    Some(engine) => engine.part_open(stream_id, &path),
                    None => Err(SESSION_UNAVAILABLE.to_string()),
                };
                match opened {
                    Ok(()) => {
                        uploads.insert(
                            stream_id,
                            Upload {
                                path,
                                next_offset: 0,
                                buffered: BTreeMap::new(),
                            },
                        );
                        reply(FileReply::WriteAck {
                            session_id,
                            stream_id,
                            received: 0,
                            error: None,
                        });
                    }
                    Err(e) => reply(FileReply::WriteAck {
                        session_id,
                        stream_id,
                        received: 0,
                        error: Some(e),
                    }),
                }
            }
            FileCommand::WriteChunk {
                session_id,
                stream_id,
                offset,
                data,
            } => {
                let response = stage_chunk(
                    backend.as_mut(),
                    &mut uploads,
                    &limits,
                    session_id,
                    stream_id,
                    offset,
                    data,
                );
                reply(response);
            }
            FileCommand::WriteEnd {
                session_id,
                stream_id,
                path,
            } => {
                let error = finish_upload(backend.as_mut(), &mut uploads, stream_id, &path).err();
                reply(FileReply::OpDone {
                    session_id,
                    op: "write_end".into(),
                    path,
                    error,
                });
            }
            FileCommand::Mkdir { session_id, path } => {
                let error = match backend.as_mut() {
                    Some(engine) => engine.mkdir(&path).err(),
                    None => Some(SESSION_UNAVAILABLE.to_string()),
                };
                reply(FileReply::OpDone {
                    session_id,
                    op: "mkdir".into(),
                    path,
                    error,
                });
            }
            FileCommand::Remove {
                session_id,
                path,
                recursive,
            } => {
                let error = match backend.as_mut() {
                    Some(engine) => engine.remove(&path, recursive).err(),
                    None => Some(SESSION_UNAVAILABLE.to_string()),
                };
                reply(FileReply::OpDone {
                    session_id,
                    op: "remove".into(),
                    path,
                    error,
                });
            }
            FileCommand::Rename {
                session_id,
                from,
                to,
            } => {
                let error = match backend.as_mut() {
                    Some(engine) => engine.rename(&from, &to).err(),
                    None => Some(SESSION_UNAVAILABLE.to_string()),
                };
                reply(FileReply::OpDone {
                    session_id,
                    op: "rename".into(),
                    path: to,
                    error: error.map(|e| format!("{e} (from {from})")),
                });
            }
        }
    }

    if let Some(engine) = backend.as_mut() {
        engine.release();
    }
    reply(FileReply::Closed {
        session_id: session_id.clone(),
        reason: "stopped".into(),
    });
}

/// Place an upload chunk, then flush whatever became contiguous.
///
/// Out-of-order chunks are buffered and drained only once the gap before them is
/// filled, so the staging file is always written sequentially and the acked
/// `received` value is a safe resume point.
fn stage_chunk(
    backend: Option<&mut Box<dyn FileBackend>>,
    uploads: &mut HashMap<u32, Upload>,
    limits: &FileLimits,
    session_id: String,
    stream_id: u32,
    offset: u64,
    data: Vec<u8>,
) -> FileReply {
    let ack = |received: u64, error: Option<String>| FileReply::WriteAck {
        session_id: session_id.clone(),
        stream_id,
        received,
        error,
    };

    let Some(upload) = uploads.get_mut(&stream_id) else {
        return ack(0, Some(format!("no upload for stream {stream_id}")));
    };
    if data.is_empty() {
        return ack(upload.next_offset, None);
    }
    let end = offset + data.len() as u64;
    if end > limits.max_upload_bytes {
        uploads.remove(&stream_id);
        if let Some(engine) = backend {
            let _ = engine.part_abort(stream_id);
        }
        return ack(
            0,
            Some(format!(
                "upload exceeds files.max_upload_bytes ({})",
                limits.max_upload_bytes
            )),
        );
    }
    if offset < upload.next_offset {
        // Bytes the browser was already acknowledged: tolerate a replay after a
        // reconnect instead of duplicating them into the staging file.
        return if end <= upload.next_offset {
            ack(upload.next_offset, None)
        } else {
            ack(
                upload.next_offset,
                Some(format!(
                    "chunk at {offset} overlaps {} staged bytes",
                    upload.next_offset
                )),
            )
        };
    }
    if offset > upload.next_offset {
        upload.buffered.insert(offset, data);
        return ack(upload.next_offset, None);
    }

    let Some(engine) = backend else {
        return ack(upload.next_offset, Some(SESSION_UNAVAILABLE.to_string()));
    };
    let mut pos = offset;
    let mut pending = Some(data);
    let mut write_error: Option<String> = None;
    while let Some(chunk) = pending.take() {
        if let Err(e) = engine.part_append(stream_id, &chunk) {
            write_error = Some(e);
            break;
        }
        pos += chunk.len() as u64;
        pending = upload.buffered.remove(&pos);
    }
    if let Some(e) = write_error {
        let _ = engine.part_abort(stream_id);
        uploads.remove(&stream_id);
        return ack(0, Some(e));
    }
    upload.next_offset = pos;
    ack(pos, None)
}

/// Commit an upload once every byte has been staged in order.
fn finish_upload(
    backend: Option<&mut Box<dyn FileBackend>>,
    uploads: &mut HashMap<u32, Upload>,
    stream_id: u32,
    path: &str,
) -> Result<(), String> {
    let Some(upload) = uploads.get(&stream_id) else {
        return Err(format!("no upload for stream {stream_id}"));
    };
    if !upload.buffered.is_empty() {
        return Err(format!(
            "upload incomplete: {} gap(s) after {} staged bytes",
            upload.buffered.len(),
            upload.next_offset
        ));
    }
    if upload.path != path {
        return Err(format!(
            "upload stream {stream_id} is for {}, not {path}",
            upload.path
        ));
    }
    let engine = backend.ok_or(SESSION_UNAVAILABLE)?;
    engine.part_commit(stream_id)?;
    uploads.remove(&stream_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nexus-file-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    fn sandbox(root: &Path, read_only: bool) -> LocalSandbox {
        let root_cfg = FileRoot {
            name: "t".into(),
            path: root.display().to_string(),
            read_only,
        };
        LocalSandbox::new(
            &root_cfg,
            FileLimits {
                chunk_bytes: 4096,
                max_upload_bytes: 1 << 20,
            },
        )
        .expect("sandbox")
    }

    fn uploads() -> HashMap<u32, Upload> {
        let mut m = HashMap::new();
        m.insert(
            1,
            Upload {
                path: "/f.bin".into(),
                next_offset: 0,
                buffered: BTreeMap::new(),
            },
        );
        m
    }

    #[test]
    fn frame_roundtrip_and_flags() {
        let bytes = b"hello file".to_vec();
        let encoded = encode_frame(FRAME_WRITE_CHUNK, 7, 4096, true, &bytes);
        assert_eq!(encoded.len(), FRAME_HEADER_LEN + bytes.len());
        let frame = decode_frame(&encoded).expect("decode");
        assert_eq!(frame.kind, FRAME_WRITE_CHUNK);
        assert_eq!(frame.stream_id, 7);
        assert_eq!(frame.offset, 4096);
        assert!(frame.final_block);
        assert_eq!(frame.data, &bytes[..]);

        let not_final = encode_frame(FRAME_READ_CHUNK, 1, 0, false, b"x");
        assert!(!decode_frame(&not_final).expect("decode").final_block);
        let empty = encode_frame(FRAME_READ_CHUNK, u32::MAX, u64::MAX, false, b"");
        let frame = decode_frame(&empty).expect("decode empty payload");
        assert_eq!((frame.stream_id, frame.offset), (u32::MAX, u64::MAX));
        assert!(frame.data.is_empty());
    }

    #[test]
    fn frame_rejects_short_and_unknown_kind() {
        assert!(decode_frame(&[FRAME_READ_CHUNK; 3]).is_err());
        assert!(decode_frame(&[]).is_err());
        let mut bad = encode_frame(FRAME_READ_CHUNK, 1, 0, false, b"a");
        bad[0] = 0x7f;
        assert!(decode_frame(&bad).is_err());
    }

    /// Byte-exact frame header fixture, shared with the page script: the same
    /// values are asserted in `static/app.js` handling, so the two codecs cannot
    /// drift apart. Layout: kind(1) | stream_id(4 BE) | offset(8 BE) | flags(1).
    #[test]
    fn frame_header_matches_the_shared_page_fixture() {
        let expected: [u8; FRAME_HEADER_LEN] = [
            0x81, 0x12, 0x34, 0x56, 0x78, // kind + stream_id 0x12345678
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, // offset 2^33 + 7
            0x01, // final flag
        ];
        let encoded = encode_frame(FRAME_WRITE_CHUNK, 0x1234_5678, (1 << 33) + 7, true, b"");
        assert_eq!(&encoded[..FRAME_HEADER_LEN], &expected);
        let decoded = decode_frame(&encoded).expect("decode fixture");
        assert_eq!(decoded.kind, FRAME_WRITE_CHUNK);
        assert_eq!(decoded.stream_id, 0x1234_5678);
        assert_eq!(decoded.offset, (1 << 33) + 7);
        assert!(decoded.final_block);
        assert!(decoded.data.is_empty());

        let with_payload = encode_frame(FRAME_READ_CHUNK, 1, 300, false, b"ab");
        assert_eq!(
            &with_payload[..FRAME_HEADER_LEN],
            &[0x01, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x2c, 0]
        );
        assert_eq!(&with_payload[FRAME_HEADER_LEN..], b"ab");
    }

    #[test]
    fn base_name_strips_the_readdir_prefix() {
        // libssh2 echoes the queried directory into readdir results.
        assert_eq!(base_name("sub/remote.txt"), "remote.txt");
        assert_eq!(base_name("remote.txt"), "remote.txt");
        assert_eq!(base_name("./x"), "x");
        assert_eq!(base_name(""), "");
    }

    #[test]
    fn normalize_rel_rules() {
        assert_eq!(normalize_rel("/").expect("root"), Vec::<String>::new());
        assert_eq!(normalize_rel("").expect("empty"), Vec::<String>::new());
        assert_eq!(
            normalize_rel("/a/./b/").expect("dots"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(normalize_rel("/../etc").is_err());
        assert!(normalize_rel("/a/../../b").is_err());
        assert!(normalize_rel("/a\\b").is_err());
        assert!(normalize_rel("/a\0b").is_err());
        assert_eq!(render_rel(&["a".into(), "b".into()]), "/a/b");
        assert_eq!(render_rel(&[]), "/");
    }

    #[test]
    fn local_sandbox_lists_stats_and_reads() {
        let root = tmp_root("list");
        fs::write(root.join("a.txt"), b"0123456789").expect("write");
        fs::create_dir_all(root.join("sub")).expect("mkdir");
        fs::write(root.join("sub").join("b.bin"), b"xyz").expect("write");

        let mut sb = sandbox(&root, false);
        let entries = sb.list("/").expect("list root");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"), "{names:?}");
        assert!(names.contains(&"sub"), "{names:?}");
        // Directories sort first for a stable UI.
        assert_eq!(entries[0].kind, "dir");

        let stat = sb.stat("/a.txt").expect("stat");
        assert_eq!(
            (stat.size, stat.kind.as_str(), stat.path.as_str()),
            (10, "file", "/a.txt")
        );

        let (data, eof) = sb.read_at(1, "/a.txt", 4, 4).expect("read middle");
        assert_eq!(&data, b"4567");
        assert!(!eof);
        let (data, eof) = sb.read_at(1, "/a.txt", 8, 8).expect("read tail");
        assert_eq!(&data, b"89");
        assert!(eof);
        let (data, eof) = sb.read_at(1, "/a.txt", 99, 8).expect("read past eof");
        assert!(data.is_empty());
        assert!(eof);
        // A second stream can read a different file concurrently.
        let (data, _) = sb.read_at(2, "/sub/b.bin", 1, 2).expect("read other");
        assert_eq!(&data, b"yz");

        let sub = sb.list("/sub").expect("list sub");
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].path, "/sub/b.bin");
        assert!(sb.stat("/missing").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_sandbox_blocks_traversal_and_symlink_escape() {
        let root = tmp_root("escape");
        let outside = tmp_root("outside");
        fs::write(outside.join("secret.txt"), b"top").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");

        let mut sb = sandbox(&root, false);
        assert!(sb.list("/../etc").is_err(), "traversal must fail");
        assert!(sb.stat("/a/../../b").is_err(), "nested traversal must fail");
        assert!(sb.read_at(1, "/..", 0, 10).is_err());
        assert!(sb.remove("/..", false).is_err());
        #[cfg(unix)]
        {
            // A symlink inside the root must not open the tree outside it.
            assert!(
                sb.list("/link").is_err(),
                "symlinked directory escaped the sandbox root"
            );
            assert!(sb.remove("/link", false).is_err());
        }
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn local_sandbox_upload_commits_atomically() {
        let root = tmp_root("upload");
        let mut sb = sandbox(&root, false);

        assert!(sb.part_open(1, "/dir/new.txt").is_err(), "missing parent");
        sb.mkdir("/dir").expect("mkdir");
        sb.part_open(1, "/dir/new.txt").expect("part_open");
        sb.part_append(1, b"hello").expect("append");
        // Nothing is visible at the final path until the commit (G14).
        assert!(!root.join("dir").join("new.txt").exists());
        sb.part_commit(1).expect("commit");
        assert_eq!(
            fs::read(root.join("dir").join("new.txt")).expect("read back"),
            b"hello"
        );
        assert_eq!(sb.list("/dir").expect("list").len(), 1);

        // An abandoned upload leaves no staging file and no target.
        sb.part_open(2, "/x.txt").expect("part_open");
        sb.part_append(2, b"partial").expect("append");
        sb.part_abort(2).expect("abort");
        let names: Vec<String> = sb
            .list("/")
            .expect("list")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(!names.iter().any(|n| n.contains("x.txt")), "{names:?}");

        // A commit without a staging file must not fabricate an empty target.
        assert!(sb.part_commit(9).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_sandbox_read_only_root_blocks_writes() {
        let root = tmp_root("readonly");
        fs::write(root.join("a.txt"), b"x").expect("write");
        let mut sb = sandbox(&root, true);
        assert!(sb.mkdir("/d").is_err());
        assert!(sb.part_open(1, "/b.txt").is_err());
        assert!(sb.remove("/a.txt", false).is_err());
        assert!(sb.rename("/a.txt", "/c.txt").is_err());
        // Reads stay available on a read-only root.
        assert!(sb.list("/").is_ok());
        assert!(sb.read_at(1, "/a.txt", 0, 8).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_sandbox_rename_and_remove() {
        let root = tmp_root("ops");
        fs::write(root.join("a.txt"), b"x").expect("write");
        fs::create_dir_all(root.join("dir")).expect("mkdir");
        fs::write(root.join("dir").join("b.txt"), b"y").expect("write");

        let mut sb = sandbox(&root, false);
        assert!(
            sb.rename("/a.txt", "/dir/b.txt").is_err(),
            "existing target"
        );
        sb.rename("/a.txt", "/c.txt").expect("rename");
        assert!(root.join("c.txt").exists());
        assert!(
            sb.remove("/dir", false).is_err(),
            "non-empty dir needs recursive"
        );
        sb.remove("/dir", true).expect("recursive remove");
        assert!(!root.join("dir").exists());
        assert!(
            sb.remove("/", true).is_err(),
            "root removal must be refused"
        );
        assert!(sb.mkdir("/").is_err(), "mkdir of the root is refused");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_chunk_drains_out_of_order_chunks_in_sequence() {
        let root = tmp_root("stage");
        let mut engine: Box<dyn FileBackend> = Box::new(sandbox(&root, false));
        engine.part_open(1, "/f.bin").expect("open");
        let mut uploads = uploads();
        let limits = FileLimits {
            chunk_bytes: 4,
            max_upload_bytes: 1 << 20,
        };

        // A chunk beyond the front is buffered, not written.
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            4,
            b"eeee".to_vec(),
        );
        assert!(
            matches!(
                r,
                FileReply::WriteAck {
                    received: 0,
                    error: None,
                    ..
                }
            ),
            "{r:?}"
        );
        assert_eq!(fs::read(root.join("f.bin")).unwrap_or_default().len(), 0);

        // Filling the front drains both chunks in order.
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            0,
            b"aaaa".to_vec(),
        );
        assert!(
            matches!(
                r,
                FileReply::WriteAck {
                    received: 8,
                    error: None,
                    ..
                }
            ),
            "gap must drain: {r:?}"
        );
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            8,
            b"ffff".to_vec(),
        );
        assert!(matches!(r, FileReply::WriteAck { received: 12, .. }));

        // A replay of already-acked bytes is tolerated and changes nothing.
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            0,
            b"aaaa".to_vec(),
        );
        assert!(matches!(
            r,
            FileReply::WriteAck {
                received: 12,
                error: None,
                ..
            }
        ));

        // An overlap (partially staged range) is refused.
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            10,
            b"zzzz".to_vec(),
        );
        assert!(matches!(r, FileReply::WriteAck { error: Some(_), .. }));

        assert!(finish_upload(Some(&mut engine), &mut uploads, 1, "/f.bin").is_ok());
        assert_eq!(fs::read(root.join("f.bin")).expect("read"), b"aaaaeeeeffff");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_chunk_rejects_unknown_stream_and_missing_backend() {
        let root = tmp_root("unknown");
        let mut engine: Box<dyn FileBackend> = Box::new(sandbox(&root, false));
        let mut uploads = uploads();
        let limits = FileLimits {
            chunk_bytes: 4,
            max_upload_bytes: 1 << 20,
        };

        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            42,
            0,
            b"x".to_vec(),
        );
        assert!(
            matches!(r, FileReply::WriteAck { error: Some(_), .. }),
            "unknown stream must error, never be ignored"
        );

        // Backend gone: the session reports it instead of swallowing the write.
        let r = stage_chunk(None, &mut uploads, &limits, "s".into(), 1, 0, b"x".to_vec());
        assert!(matches!(r, FileReply::WriteAck { error: Some(_), .. }));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn upload_enforces_size_limit_and_completeness() {
        let root = tmp_root("limits");
        let mut engine: Box<dyn FileBackend> = Box::new(sandbox(&root, false));
        let limits = FileLimits {
            chunk_bytes: 4,
            max_upload_bytes: 6,
        };

        engine.part_open(1, "/f").expect("open");
        let mut uploads = uploads();
        uploads.get_mut(&1).expect("upload").path = "/f".into();
        let r = stage_chunk(
            Some(&mut engine),
            &mut uploads,
            &limits,
            "s".into(),
            1,
            4,
            b"abcd".to_vec(),
        );
        assert!(
            matches!(r, FileReply::WriteAck { error: Some(_), .. }),
            "over-limit must error: {r:?}"
        );
        assert!(uploads.is_empty(), "a failed upload must be dropped");
        assert!(!root.join("f").exists());

        // Committing with a buffered gap must fail and leave no target file.
        engine.part_open(2, "/g").expect("open");
        let mut uploads: HashMap<u32, Upload> = HashMap::from([(
            2,
            Upload {
                path: "/g".into(),
                next_offset: 0,
                buffered: BTreeMap::from([(8, b"xxxx".to_vec())]),
            },
        )]);
        assert!(finish_upload(Some(&mut engine), &mut uploads, 2, "/g").is_err());
        assert!(!root.join("g").exists());
        // Wrong path for the stream is refused too.
        assert!(finish_upload(Some(&mut engine), &mut uploads, 2, "/other").is_err());
        assert!(finish_upload(Some(&mut engine), &mut uploads, 7, "/g").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn release_removes_staging_files() {
        let root = tmp_root("release");
        let mut sb = sandbox(&root, false);
        sb.part_open(1, "/f.txt").expect("open");
        sb.part_append(1, b"partial").expect("append");
        sb.release();
        let leftovers: Vec<String> = fs::read_dir(&root)
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging file left behind: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
