//! Linux private authority IO. No deletion or recovery by resetting metadata.
use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
use nexus_domain::task::{TaskError, TaskErrorCode};
use serde_json::{Value as Json, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(crate) const MAX_BYTES: u64 = 80 * 1024 * 1024;
pub(crate) fn corrupt(reason: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::StateCorrupt, reason, false)
}
pub(crate) fn io(error: std::io::Error) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}
pub(crate) fn sync(dir: &Path) -> Result<(), TaskError> {
    File::open(dir).map_err(io)?.sync_all().map_err(io)
}
pub(crate) fn directory(dir: &Path) -> Result<(), TaskError> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => sync(
            dir.parent()
                .ok_or_else(|| corrupt("missing authority parent"))?,
        )?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(e)),
    }
    check_directory(dir)?;
    sync(dir)
}
pub(crate) fn check_directory(dir: &Path) -> Result<(), TaskError> {
    let m = fs::symlink_metadata(dir).map_err(|e| corrupt(e.to_string()))?;
    if !m.is_dir() || m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0 {
        return Err(corrupt(
            "Artifact authority directory must be private and real",
        ));
    }
    Ok(())
}
pub(crate) fn file(path: &Path, write: bool) -> Result<File, TaskError> {
    for parent in path
        .parent()
        .ok_or_else(|| corrupt("authority parent missing"))?
        .ancestors()
    {
        let m = fs::symlink_metadata(parent).map_err(io)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(corrupt("authority parent is linked/non-directory"));
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(0x20000 | 0x800)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                corrupt(format!("missing authority: {}", path.display()))
            } else {
                io(e)
            }
        })?;
    let m = f.metadata().map_err(io)?;
    if !m.is_file() || m.permissions().mode() & 0o077 != 0 || m.nlink() != 1 {
        return Err(corrupt(
            "Artifact authority must be a private regular file without hard links",
        ));
    }
    Ok(f)
}
use std::os::unix::fs::MetadataExt;
pub(crate) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, TaskError> {
    let mut f = file(path, false)?;
    if f.metadata().map_err(io)?.len() > limit {
        return Err(corrupt("oversized Artifact authority"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limit {
        return Err(corrupt("Artifact authority grew past bound"));
    }
    f.sync_all().map_err(io)?;
    Ok(bytes)
}
pub(crate) fn canonical(value: &Json) -> Result<Vec<u8>, TaskError> {
    Ok(
        parse_canonical_json(&serde_json::to_vec(value).map_err(|e| corrupt(e.to_string()))?)?
            .canonical_bytes(),
    )
}
pub(crate) fn load(path: &Path) -> Result<Json, TaskError> {
    let raw = read(path, 8 * 1024 * 1024)?;
    let envelope: Json = serde_json::from_slice(
        &parse_canonical_json(&raw)
            .map_err(|e| corrupt(e.to_string()))?
            .canonical_bytes(),
    )
    .map_err(|e| corrupt(e.to_string()))?;
    let p = &envelope["payload"];
    if envelope.as_object().map(|m| m.len()) != Some(2)
        || envelope["checksum"] != sha256(&canonical(p)?).as_str()
    {
        return Err(corrupt("Artifact authority checksum differs"));
    }
    Ok(p.clone())
}
pub(crate) fn atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), TaskError> {
    atomic_with(dir, name, bytes, &mut |_| Ok(()))
}
pub(crate) fn atomic_with(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
) -> Result<(), TaskError> {
    let tmp = dir.join(format!(".artifact-{}.tmp", new_task_id()?.as_str()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        boundary("after_write")?;
        f.sync_all().map_err(io)?;
        boundary("after_file_sync")?;
        fs::rename(&tmp, dir.join(name)).map_err(io)?;
        boundary("after_rename")?;
        sync(dir)?;
        boundary("after_directory_sync")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub(crate) fn save(dir: &Path, name: &str, value: &Json) -> Result<(), TaskError> {
    let envelope = json!({"payload":value,"checksum":sha256(&canonical(value)?).as_str()});
    let bytes = canonical(&envelope)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(TaskError::new(
            TaskErrorCode::CapacityUnavailable,
            "Artifact metadata exceeds supported capacity",
            true,
        ));
    }
    atomic(dir, name, &bytes)
}
