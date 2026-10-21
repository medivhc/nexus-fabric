//! Private bounded Linux IO. Callers own the initialization state machine.
use super::{InitFailure, Result, corrupt, persistence};
use nexus_domain::task::TaskErrorCode;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FLAGS: i32 = 0x20000 | 0x800; // Linux O_NOFOLLOW | O_NONBLOCK.
pub(super) const SMALL: u64 = 16 * 1024;
pub(super) const AUTHORITY: u64 = 64 * 1024 * 1024;

pub(super) fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(persistence(e)),
    }
}
pub(super) fn directory(path: &Path, private: bool) -> Result<(u64, u64)> {
    let meta = fs::symlink_metadata(path).map_err(persistence)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || (private && meta.permissions().mode() & 0o777 != 0o700)
    {
        return Err(corrupt("initialization directory must be real and private"));
    }
    Ok(identity(&meta))
}
pub(super) struct Root {
    pub(super) path: PathBuf,
    pub(super) binding: (u64, u64),
    ancestors: Vec<(PathBuf, File, (u64, u64))>,
}
impl Root {
    pub(super) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(corrupt(
                "initialization root requires an absolute path without ..",
            ));
        }
        let binding = directory(path, true)?;
        let mut ancestors = Vec::new();
        for ancestor in path.ancestors() {
            let before = directory(ancestor, ancestor == path)?;
            if ancestor == path && before != binding {
                return Err(corrupt("initialization root changed before opening"));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(FLAGS)
                .open(ancestor)
                .map_err(persistence)?;
            if identity(&file.metadata().map_err(persistence)?) != before {
                return Err(corrupt("initialization ancestor changed while opening"));
            }
            ancestors.push((ancestor.to_owned(), file, before));
        }
        let root = Self {
            path: path.to_owned(),
            binding,
            ancestors,
        };
        root.check()?;
        Ok(root)
    }
    pub(super) fn check(&self) -> Result<()> {
        if directory(&self.path, true)? != self.binding {
            return Err(corrupt("original initialization root changed"));
        }
        for (path, file, binding) in &self.ancestors {
            if directory(path, path == &self.path)? != *binding
                || identity(&file.metadata().map_err(persistence)?) != *binding
            {
                return Err(corrupt("initialization root or ancestor inode changed"));
            }
        }
        Ok(())
    }
}
pub(super) struct Record {
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
    limit: u64,
    strict: bool,
}
impl Record {
    pub(super) fn binding(&self) -> Result<(u64, u64)> {
        Ok(identity(&self.file.metadata().map_err(persistence)?))
    }
    pub(super) fn check(&self) -> Result<()> {
        check_file(&self.file, &self.path, self.strict)?;
        let current = read(&self.path, self.limit, self.strict)?;
        if current.binding()? != self.binding()? || current.bytes != self.bytes {
            return Err(corrupt("original initialization record changed"));
        }
        Ok(())
    }
}
pub(super) fn check_file(file: &File, path: &Path, strict: bool) -> Result<()> {
    let fd = file.metadata().map_err(persistence)?;
    let named = fs::symlink_metadata(path).map_err(persistence)?;
    let mode = fd.permissions().mode() & 0o777;
    if !fd.is_file()
        || fd.nlink() != 1
        || named.file_type().is_symlink()
        || identity(&fd) != identity(&named)
        || if strict {
            mode != 0o600
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(corrupt(
            "initialization record must be bound, singly linked regular and private",
        ));
    }
    Ok(())
}
pub(super) fn read_optional(path: &Path, limit: u64, strict: bool) -> Result<Option<Record>> {
    let mut file = match OpenOptions::new().read(true).custom_flags(FLAGS).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if exists(path)? {
                Err(corrupt("unreadable initialization authority"))
            } else {
                Ok(None)
            };
        }
        Err(e) if e.raw_os_error() == Some(40) => {
            return Err(corrupt("linked initialization authority"));
        }
        Err(e) => return Err(persistence(e)),
    };
    check_file(&file, path, strict)?;
    if file.metadata().map_err(persistence)?.len() > limit {
        return Err(corrupt("initialization record exceeds its byte bound"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(persistence)?;
    if bytes.len() as u64 > limit {
        return Err(corrupt("initialization record grew beyond its byte bound"));
    }
    check_file(&file, path, strict)?;
    Ok(Some(Record {
        file,
        path: path.to_owned(),
        bytes,
        limit,
        strict,
    }))
}
pub(super) fn read(path: &Path, limit: u64, strict: bool) -> Result<Record> {
    read_optional(path, limit, strict)?
        .ok_or_else(|| corrupt("required initialization authority is missing"))
}
pub(super) fn sync(path: &Path) -> Result<()> {
    let before = directory(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    if identity(&file.metadata().map_err(persistence)?) != before {
        return Err(corrupt("directory changed before synchronization"));
    }
    file.sync_all().map_err(persistence)?;
    if directory(path, false)? != before {
        return Err(corrupt("directory changed during synchronization"));
    }
    Ok(())
}
pub(super) struct Lease {
    pub(super) file: File,
    path: PathBuf,
}
impl Lease {
    pub(super) fn acquire(root: &Root, path: &Path, create: bool) -> Result<Self> {
        root.check()?;
        let (file, created) = if create {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(FLAGS)
                .open(path)
            {
                Ok(file) => (file, true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(FLAGS)
                        .open(path)
                        .map_err(persistence)?;
                    check_file(&file, path, true)?;
                    nexus_platform_linux::file_lease::try_lock_exclusive(&file).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            InitFailure::new(
                                TaskErrorCode::CapacityUnavailable,
                                "initialization lease is busy",
                                true,
                            )
                        } else {
                            persistence(e)
                        }
                    })?;
                    return Err(InitFailure::new(
                        TaskErrorCode::CapacityUnavailable,
                        "provider initialization appeared concurrently; retry from its durable state",
                        true,
                    ));
                }
                Err(e) => return Err(persistence(e)),
            }
        } else {
            (
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FLAGS)
                    .open(path)
                    .map_err(persistence)?,
                false,
            )
        };
        let result = (|| {
            check_file(&file, path, true)?;
            nexus_platform_linux::file_lease::try_lock_exclusive(&file).map_err(|e| {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    InitFailure::new(
                        TaskErrorCode::CapacityUnavailable,
                        "initialization authority lease is busy",
                        true,
                    )
                } else {
                    persistence(e)
                }
            })?;
            let lease = Self {
                file,
                path: path.to_owned(),
            };
            lease.check(root)?;
            if created {
                lease.file.sync_all().map_err(persistence)?;
                sync(&root.path)?;
            }
            Ok(lease)
        })();
        result.map_err(|failure: InitFailure| {
            if created {
                failure.at("intent", true)
            } else {
                failure
            }
        })
    }
    pub(super) fn binding(&self) -> Result<(u64, u64)> {
        Ok(identity(&self.file.metadata().map_err(persistence)?))
    }
    pub(super) fn check(&self, root: &Root) -> Result<()> {
        root.check()?;
        check_file(&self.file, &self.path, true)
    }
}
pub(super) fn create_directory(root: &Root, path: &Path) -> Result<(u64, u64)> {
    root.check()?;
    for parent in path
        .parent()
        .ok_or_else(|| corrupt("directory lacks parent"))?
        .ancestors()
    {
        directory(parent, parent.starts_with(&root.path))?;
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization directory lacks parent"))?,
    )?;
    root.check()?;
    directory(path, true)
}
pub(super) fn create_file(root: &Root, path: &Path, bytes: &[u8]) -> Result<Record> {
    root.check()?;
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    check_file(&file, path, true)?;
    file.write_all(bytes).map_err(persistence)?;
    file.sync_all().map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization file lacks parent"))?,
    )?;
    root.check()?;
    check_file(&file, path, true)?;
    let published = read(path, SMALL, true)?;
    if published.binding()? != identity(&file.metadata().map_err(persistence)?)
        || published.bytes != bytes
    {
        return Err(corrupt("created initialization record was replaced"));
    }
    Ok(published)
}
pub(super) fn replace(
    root: &Root,
    path: &Path,
    before: Option<&Record>,
    bytes: &[u8],
    prepublish: impl Fn() -> Result<()>,
) -> Result<Record> {
    let check = || {
        root.check()?;
        prepublish()?;
        if let Some(before) = before {
            before.check()?;
        } else if exists(path)? {
            return Err(corrupt("initialization publication target appeared"));
        }
        Ok(())
    };
    check()?;
    let tmp = root.path.join(format!(
        ".task-provider-init-write-{}",
        nexus::n3_acceptance::new_task_id()
            .map_err(InitFailure::from)?
            .as_str()
    ));
    let temporary = create_file(root, &tmp, bytes)?;
    check()?;
    temporary.check()?;
    fs::rename(&tmp, path).map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization target lacks parent"))?,
    )?;
    root.check()?;
    let published = read(path, SMALL, true)?;
    if published.binding()? != temporary.binding()? || published.bytes != bytes {
        return Err(corrupt(
            "initialization publication changed prepared record",
        ));
    }
    Ok(published)
}
pub(super) fn publish_identity(
    root: &Root,
    source: &Record,
    target: &Path,
    prepublish: impl Fn() -> Result<()>,
) -> Result<Record> {
    root.check()?;
    prepublish()?;
    source.check()?;
    if exists(target)? {
        return Err(corrupt("identity target appeared before publication"));
    }
    // rename preserves the staged original inode; init owns this fresh N2 root.
    fs::rename(&source.path, target).map_err(persistence)?;
    sync(
        target
            .parent()
            .ok_or_else(|| corrupt("identity target lacks parent"))?,
    )?;
    sync(&root.path)?;
    root.check()?;
    prepublish()?;
    let published = read(target, SMALL, true)?;
    if published.binding()? != source.binding()? || published.bytes != source.bytes {
        return Err(corrupt("identity publication changed original material"));
    }
    Ok(published)
}
pub(super) fn sentinel(root: &Root, path: &Path, expected: &[u8]) -> Result<Record> {
    let before = read(path, SMALL, true)?;
    if before.bytes == expected {
        return Ok(before);
    }
    if !before.bytes.is_empty() {
        return Err(corrupt("unexpected capacity owner content"));
    }
    root.check()?;
    before.check()?;
    let mut writer = OpenOptions::new()
        .write(true)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    check_file(&writer, path, true)?;
    if identity(&writer.metadata().map_err(persistence)?) != before.binding()? {
        return Err(corrupt("capacity owner inode changed"));
    }
    writer.write_all(expected).map_err(persistence)?;
    writer.sync_all().map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("capacity owner lacks parent"))?,
    )?;
    let after = read(path, SMALL, true)?;
    if after.binding()? != before.binding()? || after.bytes != expected {
        return Err(corrupt("capacity owner sentinel changed"));
    }
    root.check()?;
    Ok(after)
}
