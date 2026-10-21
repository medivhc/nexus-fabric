//! Private Linux descriptor-bound IO. The caller owns transactions and durability order.
//!
//! Internal proc-fd paths resolve from retained directory descriptors; user input
//! never supplies such a path. Original names and every ancestor are rechecked.
//! Private parents and the caller's original staging lease serialize cooperating
//! writers. Name checks followed by rename/unlink are not inode-CAS operations
//! and do not promise isolation from a noncooperating process with the same UID.

#![cfg(target_os = "linux")]

use nexus_domain::task::{Sha256Digest, TaskError, TaskErrorCode};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

type IoResult<T> = Result<T, TaskError>;
const FILE_FLAGS: i32 = 0x20000 | 0x800 | 0x100; // NOFOLLOW | NONBLOCK | NOCTTY.
const DIRECTORY_FLAGS: i32 = FILE_FLAGS | 0x10000; // O_DIRECTORY.
const MAX_CHILDREN: usize = 1025;
const MAX_RANGE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NodeId {
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ReadPolicy {
    PrivateAuthority,
    ExternalBudget,
    ExistingScope,
}

#[derive(Clone)]
pub(super) struct Directory(Arc<DirectoryInner>);

struct DirectoryInner {
    file: File,
    id: NodeId,
    private: bool,
    // None is the original filesystem root, opened before any other component.
    named: Option<(Directory, OsString)>,
}

pub(super) struct Regular {
    file: File,
    parent: Directory,
    name: OsString,
    id: NodeId,
    policy: ReadPolicy,
    limit: u64,
    // Serializes writes on this handle and records the single write_new permit.
    new_empty: Mutex<bool>,
}

fn corrupt(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::StateCorrupt, reason, false)
}

fn persistence(error: io::Error) -> TaskError {
    TaskError::new(
        TaskErrorCode::PersistenceFailed,
        format!("staging IO failed: {error}"),
        true,
    )
}

fn unsupported() -> TaskError {
    TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "staging requires accessible, identity-bound Linux proc-fd directories",
        false,
    )
}

fn open_error(error: io::Error) -> TaskError {
    match error.raw_os_error() {
        Some(2 | 20 | 40) => corrupt("staging node disappeared or changed type while opening"),
        _ => persistence(error),
    }
}

fn creation_error(error: io::Error) -> TaskError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        TaskError::new(
            TaskErrorCode::CapacityUnavailable,
            "staging creation encountered an existing entry; revalidate before retrying",
            true,
        )
    } else {
        open_error(error)
    }
}

fn node_id(meta: &Metadata) -> NodeId {
    NodeId {
        device: meta.dev(),
        inode: meta.ino(),
    }
}

fn component(name: &OsStr) -> IoResult<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(corrupt("staging name must be one real host component"));
    }
    Ok(())
}

fn directory_meta(meta: &Metadata, private: bool) -> IoResult<()> {
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || (private && meta.permissions().mode() & 0o7777 != 0o700)
    {
        return Err(corrupt(
            "staging directory must be real with its required mode",
        ));
    }
    Ok(())
}

fn regular_meta(meta: &Metadata, policy: ReadPolicy, limit: u64) -> IoResult<()> {
    let mode = meta.permissions().mode() & 0o7777;
    let safe_mode = match policy {
        ReadPolicy::PrivateAuthority => mode == 0o600,
        ReadPolicy::ExternalBudget => mode & 0o022 == 0,
        ReadPolicy::ExistingScope => matches!(mode, 0o600 | 0o644),
    };
    if !meta.is_file() || meta.nlink() != 1 || !safe_mode {
        return Err(corrupt(
            "staging file must be regular, singly linked and safely permissioned",
        ));
    }
    if meta.len() > limit {
        return Err(corrupt(
            "staging file exceeds its declared physical byte bound",
        ));
    }
    Ok(())
}

fn optional_meta(path: &Path) -> IoResult<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(open_error(error)),
    }
}

impl Directory {
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.0.file.as_raw_fd()))
    }

    fn entry_path(&self, name: &OsStr) -> IoResult<PathBuf> {
        component(name)?;
        Ok(self.proc_path().join(name))
    }

    pub(super) fn id(&self) -> NodeId {
        self.0.id
    }

    pub(super) fn check(&self) -> IoResult<()> {
        let fd = self.0.file.metadata().map_err(persistence)?;
        directory_meta(&fd, self.0.private)?;
        if node_id(&fd) != self.0.id {
            return Err(corrupt("original staging directory descriptor changed"));
        }
        // This intentional internal magic-link is checked against its retained
        // descriptor. No fallback to an unpinned ordinary host path is allowed.
        let proc = fs::metadata(self.proc_path()).map_err(|_| unsupported())?;
        if !proc.is_dir() || node_id(&proc) != self.0.id {
            return Err(unsupported());
        }
        let named = if let Some((parent, name)) = &self.0.named {
            parent.check()?;
            optional_meta(&parent.entry_path(name)?)?
                .ok_or_else(|| corrupt("original staging directory name disappeared"))?
        } else {
            fs::symlink_metadata("/").map_err(open_error)?
        };
        directory_meta(&named, self.0.private)?;
        if node_id(&named) != self.0.id {
            return Err(corrupt(
                "original staging directory or ancestor name changed",
            ));
        }
        Ok(())
    }

    fn open_child(
        &self,
        name: &OsStr,
        expected: Option<NodeId>,
        private: bool,
    ) -> IoResult<Option<Directory>> {
        self.check()?;
        let path = self.entry_path(name)?;
        let Some(before) = optional_meta(&path)? else {
            self.check()?;
            return if expected.is_some() {
                Err(corrupt("original staging child directory is missing"))
            } else {
                Ok(None)
            };
        };
        directory_meta(&before, private)?;
        let id = node_id(&before);
        if expected.is_some_and(|expected| expected != id) {
            return Err(corrupt("staging child directory inode does not match"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY_FLAGS)
            .open(path)
            .map_err(open_error)?;
        let result = Directory(Arc::new(DirectoryInner {
            file,
            id,
            private,
            named: Some((self.clone(), name.to_owned())),
        }));
        result.check()?;
        Ok(Some(result))
    }

    pub(super) fn child(
        &self,
        name: &OsStr,
        expected: Option<NodeId>,
    ) -> IoResult<Option<Directory>> {
        self.open_child(name, expected, true)
    }

    pub(super) fn children(&self) -> IoResult<Vec<OsString>> {
        self.check()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(self.proc_path()).map_err(persistence)? {
            let name = entry.map_err(persistence)?.file_name();
            component(&name)?;
            if names.len() == MAX_CHILDREN {
                return Err(corrupt(
                    "staging directory exceeds the bounded enumeration cap",
                ));
            }
            // Reserve exactly; Vec's geometric growth must not exceed the cap.
            names.try_reserve_exact(1).map_err(|_| {
                persistence(io::Error::other("staging directory allocation failed"))
            })?;
            names.push(name);
        }
        names.sort();
        self.check()?;
        Ok(names)
    }
}

fn open_directory_path(path: &Path, private: bool) -> IoResult<Directory> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(corrupt(
            "staging parent requires an absolute path without ..",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY_FLAGS)
        .open("/")
        .map_err(open_error)?;
    let meta = file.metadata().map_err(persistence)?;
    directory_meta(&meta, false)?;
    let mut dir = Directory(Arc::new(DirectoryInner {
        file,
        id: node_id(&meta),
        private: private && path == Path::new("/"),
        named: None,
    }));
    dir.check()?;
    let components: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    for (index, name) in components.iter().enumerate() {
        dir = dir
            .open_child(name, None, private && index + 1 == components.len())?
            .ok_or_else(|| corrupt("required staging parent directory is missing"))?;
    }
    dir.check()?;
    Ok(dir)
}

pub(super) fn open_config_root(path: &Path) -> IoResult<Directory> {
    open_directory_path(path, true)
}

pub(super) fn open_external_parent(path: &Path) -> IoResult<Directory> {
    open_directory_path(path, false)
}

pub(super) fn open_regular(
    parent: &Directory,
    name: &OsStr,
    policy: ReadPolicy,
    limit: u64,
    expected: Option<NodeId>,
) -> IoResult<Option<Regular>> {
    parent.check()?;
    let path = parent.entry_path(name)?;
    let Some(before) = optional_meta(&path)? else {
        parent.check()?;
        return if expected.is_some() {
            Err(corrupt("original staging regular file is missing"))
        } else {
            Ok(None)
        };
    };
    regular_meta(&before, policy, limit)?;
    let id = node_id(&before);
    if expected.is_some_and(|expected| expected != id) {
        return Err(corrupt("staging regular file inode does not match"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAGS)
        .open(path)
        .map_err(open_error)?;
    let result = Regular {
        file,
        parent: parent.clone(),
        name: name.to_owned(),
        id,
        policy,
        limit,
        new_empty: Mutex::new(false),
    };
    result.check()?;
    Ok(Some(result))
}

// Size and nanosecond change times detect in-place changes around reads. The
// checked read_all/read_range also compare a second bounded byte observation.
fn same_version(a: &Metadata, b: &Metadata) -> bool {
    node_id(a) == node_id(b)
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

struct PositionedReader<'a> {
    file: &'a File,
    offset: u64,
}

impl Read for PositionedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("staging read offset overflow"))?;
        Ok(count)
    }
}

impl Regular {
    pub(super) fn id(&self) -> NodeId {
        self.id
    }

    pub(super) fn check(&self) -> IoResult<()> {
        self.parent.check()?;
        let fd = self.file.metadata().map_err(persistence)?;
        let named = optional_meta(&self.parent.entry_path(&self.name)?)?
            .ok_or_else(|| corrupt("original staging regular file name disappeared"))?;
        regular_meta(&fd, self.policy, self.limit)?;
        regular_meta(&named, self.policy, self.limit)?;
        if node_id(&fd) != self.id || node_id(&named) != self.id {
            return Err(corrupt(
                "original staging regular file descriptor or name changed",
            ));
        }
        self.parent.check()?;
        Ok(())
    }

    pub(super) fn len(&self) -> IoResult<u64> {
        self.check()?;
        let len = self.file.metadata().map_err(persistence)?.len();
        self.check()?;
        Ok(len)
    }

    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> IoResult<()> {
        match self.file.read_exact_at(bytes, offset) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                Err(corrupt("staging file ended before its declared range"))
            }
            Err(error) => Err(persistence(error)),
        }
    }

    fn verify_bytes(&self, offset: u64, bytes: &[u8]) -> IoResult<()> {
        let mut scratch = [0u8; MAX_RANGE];
        let mut checked = 0usize;
        while checked < bytes.len() {
            let count = (bytes.len() - checked).min(scratch.len());
            let at = offset
                .checked_add(checked as u64)
                .ok_or_else(|| corrupt("staging verification range overflow"))?;
            self.read_exact_at(at, &mut scratch[..count])?;
            if scratch[..count] != bytes[checked..checked + count] {
                return Err(corrupt(
                    "staging file bytes changed during reading or writing",
                ));
            }
            checked += count;
        }
        Ok(())
    }

    fn finish_read(&self, before: &Metadata) -> IoResult<()> {
        self.check()?;
        let after = self.file.metadata().map_err(persistence)?;
        if !same_version(before, &after) {
            return Err(corrupt("staging file changed during a bounded read"));
        }
        Ok(())
    }

    pub(super) fn read_all(&self) -> IoResult<Vec<u8>> {
        self.check()?;
        let before = self.file.metadata().map_err(persistence)?;
        regular_meta(&before, self.policy, self.limit)?;
        let length = usize::try_from(before.len())
            .map_err(|_| corrupt("staging read length exceeds host allocation range"))?;
        let take = self
            .limit
            .checked_add(1)
            .ok_or_else(|| corrupt("staging read limit overflow"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| persistence(io::Error::other("staging bounded read allocation failed")))?;
        // Allocation is bounded by the already checked physical declaration.
        // Read::take additionally prevents a racing grow from becoming unbounded.
        let mut reader = PositionedReader {
            file: &self.file,
            offset: 0,
        }
        .take(take);
        let mut scratch = [0u8; MAX_RANGE];
        loop {
            let count = loop {
                match reader.read(&mut scratch) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => break result.map_err(persistence)?,
                }
            };
            if count == 0 {
                break;
            }
            if count > length.saturating_sub(bytes.len()) {
                return Err(corrupt("staging file grew beyond its declared read length"));
            }
            bytes.extend_from_slice(&scratch[..count]);
        }
        if bytes.len() != length {
            return Err(corrupt(
                "staging file ended before its declared read length",
            ));
        }
        self.verify_bytes(0, &bytes)?;
        self.finish_read(&before)?;
        Ok(bytes)
    }

    pub(super) fn read_range(&self, offset: u64, length: usize) -> IoResult<Vec<u8>> {
        self.check()?;
        let before = self.file.metadata().map_err(persistence)?;
        regular_meta(&before, self.policy, self.limit)?;
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| corrupt("staging read range overflow"))?;
        if length > MAX_RANGE || end > before.len() || end > self.limit {
            return Err(corrupt("staging read range exceeds its declared bound"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| persistence(io::Error::other("staging range allocation failed")))?;
        bytes.resize(length, 0);
        self.read_exact_at(offset, &mut bytes)?;
        self.verify_bytes(offset, &bytes)?;
        self.finish_read(&before)?;
        Ok(bytes)
    }

    pub(super) fn hash_prefix(&self, prefix_len: u64) -> IoResult<Sha256Digest> {
        self.check()?;
        let before = self.file.metadata().map_err(persistence)?;
        regular_meta(&before, self.policy, self.limit)?;
        if prefix_len > before.len() || prefix_len > self.limit {
            return Err(corrupt(
                "staging hash prefix exceeds the declared physical range",
            ));
        }
        let mut reader = PositionedReader {
            file: &self.file,
            offset: 0,
        }
        .take(prefix_len);
        let digest = nexus::n3_acceptance::sha256_reader(&mut reader).map_err(persistence)?;
        if reader.limit() != 0 {
            return Err(corrupt(
                "staging file ended before the declared hash prefix",
            ));
        }
        self.finish_read(&before)?;
        Ok(digest)
    }

    fn writer(&self) -> IoResult<File> {
        self.check()?;
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAGS)
            .open(self.parent.entry_path(&self.name)?)
            .map_err(open_error)?;
        let meta = file.metadata().map_err(persistence)?;
        regular_meta(&meta, self.policy, self.limit)?;
        if node_id(&meta) != self.id {
            return Err(corrupt("staging writer opened a replacement inode"));
        }
        self.check()?;
        Ok(file)
    }
}

pub(super) fn create_directory(parent: &Directory, name: &OsStr) -> IoResult<Directory> {
    parent.check()?;
    // Only private directories admit mutations through this API.
    directory_meta(&parent.0.file.metadata().map_err(persistence)?, true)?;
    let path = parent.entry_path(name)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(creation_error)?;
    parent
        .child(name, None)?
        .ok_or_else(|| corrupt("created staging directory disappeared"))
}

pub(super) fn create_file(parent: &Directory, name: &OsStr, limit: u64) -> IoResult<Regular> {
    parent.check()?;
    directory_meta(&parent.0.file.metadata().map_err(persistence)?, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(FILE_FLAGS)
        .open(parent.entry_path(name)?)
        .map_err(creation_error)?;
    let id = node_id(&file.metadata().map_err(persistence)?);
    let result = Regular {
        file,
        parent: parent.clone(),
        name: name.to_owned(),
        id,
        policy: ReadPolicy::PrivateAuthority,
        limit,
        new_empty: Mutex::new(true),
    };
    result.check()?;
    Ok(result)
}

pub(super) fn write_new(file: &Regular, bytes: &[u8]) -> IoResult<()> {
    let mut permit = file
        .new_empty
        .lock()
        .map_err(|_| corrupt("staging write ownership was poisoned"))?;
    file.check()?;
    if !*permit || file.len()? != 0 || bytes.len() as u64 > file.limit {
        return Err(corrupt(
            "staging new write requires its original newly created empty inode",
        ));
    }
    directory_meta(&file.parent.0.file.metadata().map_err(persistence)?, true)?;
    let writer = file.writer()?;
    *permit = false;
    writer.write_all_at(bytes, 0).map_err(persistence)?;
    file.check()?;
    if file.len()? != bytes.len() as u64 {
        return Err(corrupt(
            "staging new write did not preserve its exact length",
        ));
    }
    file.verify_bytes(0, bytes)?;
    file.check()
}

pub(super) fn append(file: &Regular, old_len: u64, bytes: &[u8]) -> IoResult<()> {
    let mut permit = file
        .new_empty
        .lock()
        .map_err(|_| corrupt("staging write ownership was poisoned"))?;
    file.check()?;
    let end = old_len
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| corrupt("staging append range overflow"))?;
    if !matches!(file.policy, ReadPolicy::PrivateAuthority)
        || file.len()? != old_len
        || end > file.limit
    {
        return Err(corrupt(
            "staging append requires the exact existing physical prefix length",
        ));
    }
    directory_meta(&file.parent.0.file.metadata().map_err(persistence)?, true)?;
    let writer = file.writer()?;
    if writer.metadata().map_err(persistence)?.len() != old_len {
        return Err(corrupt("staging blob changed before append"));
    }
    *permit = false;
    writer.write_all_at(bytes, old_len).map_err(persistence)?;
    file.check()?;
    if file.len()? != end {
        return Err(corrupt(
            "staging append did not preserve its exact declared range",
        ));
    }
    file.verify_bytes(old_len, bytes)?;
    file.check()
}

pub(super) fn sync_file(file: &Regular) -> IoResult<()> {
    file.check()?;
    file.file.sync_all().map_err(persistence)?;
    file.check()
}

pub(super) fn sync_directory(dir: &Directory) -> IoResult<()> {
    dir.check()?;
    dir.0.file.sync_all().map_err(persistence)?;
    dir.check()
}

pub(super) fn publish(
    source: Regular,
    target_parent: &Directory,
    target_name: &OsStr,
    expected: Option<&Regular>,
) -> IoResult<Regular> {
    source.check()?;
    target_parent.check()?;
    directory_meta(&source.parent.0.file.metadata().map_err(persistence)?, true)?;
    directory_meta(&target_parent.0.file.metadata().map_err(persistence)?, true)?;
    if source.id.device != target_parent.id().device
        || !matches!(source.policy, ReadPolicy::PrivateAuthority)
    {
        return Err(corrupt(
            "staging publication requires private nodes on one device",
        ));
    }
    let from = source.parent.entry_path(&source.name)?;
    let to = target_parent.entry_path(target_name)?;
    if let Some(expected) = expected {
        expected.check()?;
        if expected.parent.id() != target_parent.id()
            || expected.name != target_name
            || expected.id == source.id
            || !matches!(expected.policy, ReadPolicy::PrivateAuthority)
        {
            return Err(corrupt(
                "staging publication destination is not the originally opened target",
            ));
        }
        source.check()?;
        target_parent.check()?;
        expected.check()?;
        fs::rename(from, to).map_err(persistence)?;
    } else {
        if optional_meta(&to)?.is_some() {
            return Err(corrupt("staging no-replace destination already exists"));
        }
        source.check()?;
        target_parent.check()?;
        nexus_platform_linux::directory_publish::publish_directory_no_replace(&from, &to).map_err(
            |error| {
                if error.kind() == io::ErrorKind::Unsupported {
                    TaskError::new(
                        TaskErrorCode::UnsupportedCapability,
                        "staging requires atomic no-replace publication",
                        false,
                    )
                } else if error.kind() == io::ErrorKind::AlreadyExists {
                    corrupt("staging publication destination appeared")
                } else {
                    persistence(error)
                }
            },
        )?;
    }
    source.parent.check()?;
    target_parent.check()?;
    if optional_meta(&source.parent.entry_path(&source.name)?)?.is_some() {
        return Err(corrupt(
            "staging publication source name remained or reappeared",
        ));
    }
    if let Some(expected) = expected {
        let replaced = expected.file.metadata().map_err(persistence)?;
        if node_id(&replaced) != expected.id
            || !replaced.is_file()
            || replaced.permissions().mode() & 0o7777 != 0o600
            || replaced.nlink() != 0
            || replaced.len() > expected.limit
        {
            return Err(corrupt(
                "staging publication did not replace the original destination inode",
            ));
        }
    }
    let result = Regular {
        file: source.file,
        parent: target_parent.clone(),
        name: target_name.to_owned(),
        id: source.id,
        policy: source.policy,
        limit: source.limit,
        new_empty: Mutex::new(false),
    };
    result.check()?;
    Ok(result)
}

pub(super) fn remove_file(file: &Regular) -> IoResult<()> {
    file.check()?;
    directory_meta(&file.parent.0.file.metadata().map_err(persistence)?, true)?;
    if !matches!(file.policy, ReadPolicy::PrivateAuthority) {
        return Err(corrupt(
            "staging deletion requires a private owned regular inode",
        ));
    }
    fs::remove_file(file.parent.entry_path(&file.name)?).map_err(persistence)?;
    file.parent.check()?;
    let meta = file.file.metadata().map_err(persistence)?;
    if node_id(&meta) != file.id
        || !meta.is_file()
        || meta.permissions().mode() & 0o7777 != 0o600
        || meta.nlink() != 0
        || meta.len() > file.limit
        || optional_meta(&file.parent.entry_path(&file.name)?)?.is_some()
    {
        return Err(corrupt(
            "staging deletion did not remove exactly its original inode",
        ));
    }
    Ok(())
}

pub(super) fn remove_empty_directory(dir: &Directory) -> IoResult<()> {
    dir.check()?;
    let Some((parent, name)) = &dir.0.named else {
        return Err(corrupt("staging cannot remove the filesystem root"));
    };
    directory_meta(&dir.0.file.metadata().map_err(persistence)?, true)?;
    directory_meta(&parent.0.file.metadata().map_err(persistence)?, true)?;
    if !dir.children()?.is_empty() {
        return Err(corrupt(
            "staging directory deletion requires an empty owned directory",
        ));
    }
    dir.check()?;
    fs::remove_dir(parent.entry_path(name)?).map_err(persistence)?;
    parent.check()?;
    let meta = dir.0.file.metadata().map_err(persistence)?;
    if node_id(&meta) != dir.id()
        || !meta.is_dir()
        || meta.permissions().mode() & 0o7777 != 0o700
        || meta.nlink() != 0
        || optional_meta(&parent.entry_path(name)?)?.is_some()
    {
        return Err(corrupt(
            "staging directory deletion did not remove its original inode",
        ));
    }
    Ok(())
}

pub(super) struct ExclusiveLease {
    original: Regular,
}

pub(super) fn try_exclusive(
    parent: &Directory,
    name: &OsStr,
    expected: NodeId,
) -> IoResult<ExclusiveLease> {
    parent.check()?;
    directory_meta(&parent.0.file.metadata().map_err(persistence)?, true)?;
    // A fresh open creates a distinct file description; never File::try_clone.
    let original = open_regular(
        parent,
        name,
        ReadPolicy::PrivateAuthority,
        0,
        Some(expected),
    )?
    .ok_or_else(|| corrupt("original staging lease inode is missing"))?;
    nexus_platform_linux::file_lease::try_lock_exclusive(&original.file).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            TaskError::new(
                TaskErrorCode::CapacityUnavailable,
                "original staging lease is busy",
                true,
            )
        } else {
            persistence(error)
        }
    })?;
    let lease = ExclusiveLease { original };
    lease.check()?;
    Ok(lease)
}

impl ExclusiveLease {
    pub(super) fn check(&self) -> IoResult<()> {
        self.original.check()
    }
}
