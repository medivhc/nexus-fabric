//! Narrow private Linux IO for the scoped operator boundary.
use super::super::{Failure, Result};
use nexus_domain::task::TaskErrorCode;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FLAGS: i32 = 0x20000 | 0x800; // Linux O_NOFOLLOW | O_NONBLOCK.
pub(super) const RECORD_LIMIT: u64 = 16 * 1024;

pub(super) fn corrupt(reason: impl Into<String>) -> Failure {
    Failure::new(TaskErrorCode::StateCorrupt, reason, false)
}
pub(super) fn persistence(error: impl std::fmt::Display) -> Failure {
    Failure::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}
pub(super) fn capacity(reason: &str, retryable: bool) -> Failure {
    Failure::new(TaskErrorCode::CapacityUnavailable, reason, retryable)
}
pub(super) fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn real_ancestors(path: &Path) -> Result<()> {
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent).map_err(persistence)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(corrupt("operator root ancestor must be a real directory"));
        }
    }
    Ok(())
}
fn private_directory(path: &Path) -> Result<(u64, u64)> {
    real_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(persistence)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(corrupt("operator config and N2 roots must be 0700"));
    }
    Ok(identity(&metadata))
}
pub(super) struct Roots {
    pub(super) config: PathBuf,
    pub(super) n2: PathBuf,
    config_identity: (u64, u64),
    n2_identity: (u64, u64),
}
impl Roots {
    pub(super) fn open(config: &Path) -> Result<Self> {
        let config_identity = private_directory(config)?;
        let n2 = config.join("n2");
        let n2_identity = private_directory(&n2)?;
        Ok(Self {
            config: config.to_owned(),
            n2,
            config_identity,
            n2_identity,
        })
    }
    pub(super) fn check(&self) -> Result<()> {
        if private_directory(&self.config)? != self.config_identity
            || private_directory(&self.n2)? != self.n2_identity
        {
            return Err(corrupt("operator root inode changed"));
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
            mode != 0o600 && mode != 0o644
        }
    {
        return Err(corrupt(
            "operator file must be regular, singly linked, bound and private",
        ));
    }
    Ok(())
}
pub(super) struct Record {
    pub(super) file: File,
    pub(super) bytes: Vec<u8>,
}
pub(super) fn read_optional(path: &Path, limit: u64, strict: bool) -> Result<Option<Record>> {
    let mut file = match OpenOptions::new().read(true).custom_flags(FLAGS).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Broken symlinks are not absent authority.
            return match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Ok(_) => Err(corrupt("operator authority entry is not readable")),
                Err(error) => Err(persistence(error)),
            };
        }
        Err(error) => return Err(persistence(error)),
    };
    check_file(&file, path, strict)?;
    if file.metadata().map_err(persistence)?.len() > limit {
        return Err(capacity("operator authority exceeds its byte bound", false));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(persistence)?;
    if bytes.len() as u64 > limit {
        return Err(capacity(
            "operator authority grew beyond its byte bound",
            false,
        ));
    }
    check_file(&file, path, strict)?;
    Ok(Some(Record { file, bytes }))
}
pub(super) fn read(path: &Path, strict: bool) -> Result<Record> {
    read_optional(path, RECORD_LIMIT, strict)?
        .ok_or_else(|| corrupt("existing operator authority is missing"))
}
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .map_err(persistence)?
        .sync_all()
        .map_err(persistence)
}
pub(super) struct Lease {
    file: File,
    path: PathBuf,
}
impl Lease {
    pub(super) fn acquire(roots: &Roots) -> Result<Self> {
        roots.check()?;
        let path = roots.n2.join("task-provider-grants.lock");
        let (file, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(FLAGS)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(FLAGS)
                    .open(&path)
                    .map_err(persistence)?,
                false,
            ),
            Err(error) => return Err(persistence(error)),
        };
        check_file(&file, &path, true)?;
        nexus_platform_linux::file_lease::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                capacity("operator grant lease is busy", true)
            } else {
                persistence(error)
            }
        })?;
        let lease = Self { file, path };
        lease.check(roots)?;
        if created {
            lease.file.sync_all().map_err(persistence)?;
            sync_directory(&roots.n2)?;
        }
        Ok(lease)
    }
    pub(super) fn check(&self, roots: &Roots) -> Result<()> {
        roots.check()?;
        check_file(&self.file, &self.path, true)
    }
}
pub(super) fn append(
    roots: &Roots,
    lease: &Lease,
    path: &Path,
    previous: Option<&File>,
    expected_length: u64,
    bytes: &[u8],
) -> Result<File> {
    lease.check(roots)?;
    let file = if let Some(previous) = previous {
        check_file(previous, path, true)?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .custom_flags(FLAGS)
            .open(path)
            .map_err(persistence)?;
        if identity(&file.metadata().map_err(persistence)?)
            != identity(&previous.metadata().map_err(persistence)?)
        {
            return Err(corrupt("operator audit inode changed"));
        }
        file
    } else {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(FLAGS)
            .open(path)
            .map_err(persistence)?;
        file.sync_all().map_err(persistence)?;
        sync_directory(&roots.n2)?;
        lease.check(roots)?;
        file
    };
    check_file(&file, path, true)?;
    if file.metadata().map_err(persistence)?.len() != expected_length {
        return Err(corrupt("operator audit length changed"));
    }
    let mut writer = &file;
    writer.write_all(bytes).map_err(persistence)?;
    file.sync_all().map_err(persistence)?;
    sync_directory(&roots.n2)?;
    lease.check(roots)?;
    check_file(&file, path, true)?;
    Ok(file)
}
pub(super) fn atomic_grant(
    roots: &Roots,
    lease: &Lease,
    path: &Path,
    before: Option<&Record>,
    bytes: &[u8],
    prepublish: impl Fn() -> Result<()>,
) -> Result<()> {
    lease.check(roots)?;
    check_grant_before(path, before)?;
    let name = crate::n3_acceptance::new_task_id().map_err(|error| Failure {
        error,
        phase: "grant_write",
        may_have_applied: false,
    })?;
    let temporary = roots
        .n2
        .join(format!(".task-provider-grant-{}.tmp", name.as_str()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(FLAGS)
        .open(&temporary)
        .map_err(persistence)?;
    // A failed write retains its own temporary file for inspection. It is not authority.
    file.write_all(bytes).map_err(persistence)?;
    file.sync_all().map_err(persistence)?;
    check_file(&file, &temporary, true)?;
    // Recheck every caller-owned scope/identity binding after temporary IO,
    // then compare the original grant descriptor as well as its raw bytes.
    prepublish()?;
    check_grant_before(path, before)?;
    lease.check(roots)?;
    fs::rename(&temporary, path).map_err(|error| persistence(error).at("grant_publish", true))?;
    #[cfg(test)]
    test_fault("after_grant_rename").map_err(|error| error.at("grant_sync", true))?;
    sync_directory(&roots.n2).map_err(|error| error.at("grant_sync", true))?;
    lease
        .check(roots)
        .map_err(|error| error.at("grant_sync", true))?;
    check_file(&file, path, true).map_err(|error| error.at("grant_sync", true))?;
    Ok(())
}

pub(super) fn check_grant_before(path: &Path, before: Option<&Record>) -> Result<()> {
    if let Some(before) = before {
        check_file(&before.file, path, false)?;
    }
    let current = read_optional(path, RECORD_LIMIT, false)?;
    if current.as_ref().map(|record| record.bytes.as_slice())
        != before.map(|record| record.bytes.as_slice())
    {
        return Err(corrupt("target grant changed outside the operator lease"));
    }
    // Reading a new descriptor must not silently substitute the original inode.
    if let Some(before) = before {
        check_file(&before.file, path, false)?;
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    static FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(super) fn set_test_fault(name: &'static str) {
    FAULT.with(|fault| fault.set(Some(name)));
}
#[cfg(test)]
fn test_fault(name: &str) -> Result<()> {
    if FAULT.with(|fault| {
        if fault.get() == Some(name) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        Err(persistence("injected durable-boundary failure"))
    } else {
        Ok(())
    }
}
