//! Linux local receiver. A transport supplies authorized byte pages; this type
//! does not fetch data or trust storage_ref. Persistent partial data is private.
use crate::artifact_fs as disk;
use nexus::n3_acceptance::sha256;
use nexus_domain::task::{codec::CanonicalDto, *};
use serde_json::{Value as Json, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

/// One stable cross-process lease owns a destination's receiving/publication.
/// Restart resumes only checksum-consistent bytes; torn state is preserved.
pub struct ArtifactDownload {
    directory: PathBuf,
    destination: PathBuf,
    artifact: ArtifactRecord,
    progress: Json,
    _lease: File,
}
impl ArtifactDownload {
    pub fn open(artifact: &ArtifactRecord, destination: &Path) -> Result<Self, TaskError> {
        artifact.validate()?;
        if artifact.publication_state != PublicationState::Published
            || artifact.size_bytes > disk::MAX_BYTES
        {
            return Err(TaskError::new(
                TaskErrorCode::ArtifactUnavailable,
                "download requires a bounded Published Artifact",
                false,
            ));
        }
        let destination = absolute_destination(destination)?;
        let parent = destination
            .parent()
            .ok_or_else(|| TaskError::invalid("destination has no parent"))?;
        let directory = parent.join(format!(
            ".nexus-artifact-{}",
            &sha256(destination.as_os_str().as_encoded_bytes()).as_str()[7..]
        ));
        if fs::symlink_metadata(&directory).is_err() && fs::symlink_metadata(&destination).is_ok() {
            return Err(exists());
        }
        let fresh = match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {
                disk::sync(parent)?;
                disk::check_directory(&directory)?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                disk::check_directory(&directory)?;
                false
            }
            Err(e) => return Err(disk::io(e)),
        };
        let lease_path = directory.join("receiver.lock");
        if !fresh {
            disk::file(&lease_path, false)?;
        }
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&lease_path)
        {
            Ok(f) => {
                f.sync_all().map_err(disk::io)?;
                disk::sync(&directory)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(disk::io(e)),
        }
        let lease = disk::file(&lease_path, true)?;
        lock(&lease)?;
        let artifact_json: Json = serde_json::from_slice(&artifact.to_value().canonical_bytes())
            .map_err(|e| disk::corrupt(e.to_string()))?;
        let progress = match fs::symlink_metadata(directory.join("progress-v1.json")) {
            Ok(_) => disk::load(&directory.join("progress-v1.json"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !fresh {
                    return Err(disk::corrupt(
                        "initialized download progress missing; preserve authority",
                    ));
                }
                if fs::symlink_metadata(directory.join("partial")).is_ok() {
                    return Err(disk::corrupt("download progress lost beside partial data"));
                }
                if fs::symlink_metadata(&destination).is_ok() {
                    return Err(exists());
                }
                let f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(directory.join("partial"))
                    .map_err(disk::io)?;
                f.sync_all().map_err(disk::io)?;
                disk::sync(&directory)?;
                let value = json!({"schema_version":1,"artifact":artifact_json,"destination":destination.to_str().ok_or_else(||TaskError::invalid("non UTF-8 output path"))?,
                    "offset":0,"prefix_sha256":sha256(b"").as_str(),"phase":"Receiving"});
                disk::save(&directory, "progress-v1.json", &value)?;
                value
            }
            Err(e) => return Err(disk::io(e)),
        };
        let receiver = Self {
            directory,
            destination,
            artifact: artifact.clone(),
            progress,
            _lease: lease,
        };
        receiver.validate(&artifact_json)?;
        Ok(receiver)
    }
    pub fn offset(&self) -> u64 {
        self.progress["offset"].as_u64().unwrap_or(0)
    }
    /// Replayed wholly committed pages are acknowledged only if bytes match.
    /// Partial overlaps and gaps are rejected; no truncation/restart is inferred.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) -> Result<u64, TaskError> {
        self.check_current()?;
        if self.progress["phase"] != "Receiving" || bytes.is_empty() || bytes.len() > 65536 {
            return Err(TaskError::invalid(
                "download expects a nonempty 1..65536 byte page while receiving",
            ));
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.artifact.size_bytes)
            .ok_or_else(|| TaskError::invalid("download page exceeds expected length"))?;
        let committed = self.offset();
        let mut partial = self.partial(true)?;
        if end <= committed {
            partial.seek(SeekFrom::Start(offset)).map_err(disk::io)?;
            let mut old = vec![0; bytes.len()];
            partial.read_exact(&mut old).map_err(disk::io)?;
            if old != bytes {
                return Err(integrity("replayed download page changed"));
            }
            disk::sync(&self.directory)?;
            return Ok(committed);
        }
        if offset != committed {
            return Err(TaskError::invalid(
                "download page offset is not the durable resume offset",
            ));
        }
        partial.seek(SeekFrom::Start(offset)).map_err(disk::io)?;
        partial.write_all(bytes).map_err(disk::io)?;
        partial.sync_all().map_err(disk::io)?;
        let prefix = self.bytes()?;
        let mut next = self.progress.clone();
        next["offset"] = json!(end);
        next["prefix_sha256"] = json!(sha256(&prefix).as_str());
        disk::save(&self.directory, "progress-v1.json", &next)?;
        self.progress = next;
        Ok(end)
    }
    /// SHA-256/length verified before atomic no-replace hard-link publication.
    /// A crash after the link resumes using same inode, never overwrites another file.
    pub fn finish(&mut self) -> Result<PathBuf, TaskError> {
        self.finish_with(&mut |_| Ok(()))
    }
    fn finish_with(
        &mut self,
        boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<PathBuf, TaskError> {
        self.check_current()?;
        let bytes = self.bytes()?;
        if bytes.len() as u64 != self.artifact.size_bytes
            || sha256(&bytes) != self.artifact.content_sha256
        {
            return Err(integrity(
                "download SHA-256/length differs from Artifact record",
            ));
        }
        if self.progress["phase"] == "Receiving" {
            if fs::symlink_metadata(&self.destination).is_ok() {
                return Err(exists());
            }
            let mut next = self.progress.clone();
            next["phase"] = json!("Publishing");
            disk::save(&self.directory, "progress-v1.json", &next)?;
            self.progress = next;
            boundary("after_publish_intent")?;
        }
        match fs::hard_link(self.directory.join("partial"), &self.destination) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self.own_destination()?,
            Err(e) => return Err(disk::io(e)),
        }
        boundary("after_link")?;
        self.partial(false)?.sync_all().map_err(disk::io)?;
        disk::sync(
            self.destination
                .parent()
                .ok_or_else(|| disk::corrupt("output parent missing"))?,
        )?;
        disk::sync(&self.directory)?;
        boundary("after_destination_sync")?;
        let mut next = self.progress.clone();
        next["phase"] = json!("Published");
        disk::save(&self.directory, "progress-v1.json", &next)?;
        self.progress = next;
        Ok(self.destination.clone())
    }
    fn validate(&self, artifact_json: &Json) -> Result<(), TaskError> {
        if self.progress.as_object().map(|m| m.len()) != Some(6)
            || self.progress["schema_version"] != 1
            || self.progress["artifact"] != *artifact_json
            || self.progress["destination"] != self.destination.to_str().unwrap_or("")
            || !self.progress["offset"].is_u64()
            || self.offset() > self.artifact.size_bytes
            || !["Receiving", "Publishing", "Published"]
                .iter()
                .any(|p| self.progress["phase"] == *p)
        {
            return Err(disk::corrupt(
                "download progress belongs to another Artifact/output or has invalid fields",
            ));
        }
        let bytes = self.bytes()?;
        if bytes.len() as u64 != self.offset()
            || self.progress["prefix_sha256"] != sha256(&bytes).as_str()
        {
            return Err(integrity(
                "partial bytes differ from durable progress; preserve for reconciliation",
            ));
        }
        if self.progress["phase"] != "Receiving"
            && (self.offset() != self.artifact.size_bytes
                || sha256(&bytes) != self.artifact.content_sha256)
        {
            return Err(integrity(
                "publication receipt lacks complete verified data",
            ));
        }
        match fs::symlink_metadata(&self.destination) {
            Ok(_) if self.progress["phase"] == "Receiving" => Err(exists()),
            Ok(_) => self.own_destination(),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && self.progress["phase"] != "Published" =>
            {
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(disk::corrupt("published download destination lost"))
            }
            Err(e) => Err(disk::io(e)),
        }
    }
    fn check_current(&self) -> Result<(), TaskError> {
        disk::check_directory(&self.directory)?;
        let current = disk::file(&self.directory.join("receiver.lock"), false)?
            .metadata()
            .map_err(disk::io)?;
        let owned = self._lease.metadata().map_err(disk::io)?;
        if current.dev() != owned.dev() || current.ino() != owned.ino() {
            return Err(disk::corrupt("download lease inode changed"));
        }
        let persisted = disk::load(&self.directory.join("progress-v1.json"))?;
        if persisted != self.progress {
            return Err(disk::corrupt("download progress changed; reopen required"));
        }
        let artifact: Json = serde_json::from_slice(&self.artifact.to_value().canonical_bytes())
            .map_err(|e| disk::corrupt(e.to_string()))?;
        self.validate(&artifact)
    }
    fn partial(&self, write: bool) -> Result<File, TaskError> {
        let f = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(0x20000 | 0x800)
            .open(self.directory.join("partial"))
            .map_err(disk::io)?;
        let m = f.metadata().map_err(disk::io)?;
        if !m.is_file()
            || m.permissions().mode() & 0o077 != 0
            || m.len() > disk::MAX_BYTES
            || m.nlink() != 1 && !(m.nlink() == 2 && self.progress["phase"] != "Receiving")
        {
            return Err(disk::corrupt(
                "partial download must be private regular bytes",
            ));
        }
        Ok(f)
    }
    fn bytes(&self) -> Result<Vec<u8>, TaskError> {
        let mut f = self.partial(false)?;
        let mut b = Vec::new();
        Read::by_ref(&mut f)
            .take(disk::MAX_BYTES + 1)
            .read_to_end(&mut b)
            .map_err(disk::io)?;
        if b.len() as u64 > disk::MAX_BYTES {
            return Err(integrity("download exceeded adapter bound"));
        }
        Ok(b)
    }
    fn own_destination(&self) -> Result<(), TaskError> {
        let source = self.partial(false)?.metadata().map_err(disk::io)?;
        let dest = fs::symlink_metadata(&self.destination).map_err(disk::io)?;
        if dest.is_file()
            && !dest.file_type().is_symlink()
            && dest.dev() == source.dev()
            && dest.ino() == source.ino()
        {
            Ok(())
        } else {
            Err(exists())
        }
    }
}
fn absolute_destination(path: &Path) -> Result<PathBuf, TaskError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(disk::io)?.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| TaskError::invalid("invalid output path"))?;
    for dir in parent.ancestors() {
        let m = fs::symlink_metadata(dir).map_err(disk::io)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(TaskError::new(
                TaskErrorCode::InvalidPath,
                "output parent must not contain links",
                false,
            ));
        }
    }
    let name = absolute
        .file_name()
        .ok_or_else(|| TaskError::invalid("output file name missing"))?;
    if name.to_str().is_none() {
        return Err(TaskError::invalid("non UTF-8 output name"));
    }
    Ok(parent.canonicalize().map_err(disk::io)?.join(name))
}
fn lock(file: &File) -> Result<(), TaskError> {
    unsafe extern "C" {
        fn flock(fd: std::ffi::c_int, op: std::ffi::c_int) -> std::ffi::c_int;
    }
    loop {
        // SAFETY: owned live fd; LOCK_EX has no pointers or retained references.
        if unsafe { flock(file.as_raw_fd(), 2) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(disk::io(e));
        }
    }
}
fn integrity(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::ArtifactIntegrityFailed, reason, false)
}
fn exists() -> TaskError {
    TaskError::new(
        TaskErrorCode::OutputExists,
        "download output already exists",
        false,
    )
}
#[cfg(test)]
#[path = "artifact_download_tests.rs"]
mod tests;
