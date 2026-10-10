//! Linux requester cache/outbox, independent of provider acceptance authority.
//! Authentication/transport are composition-root prerequisites, not implemented here.
use crate::artifact_fs as disk;
use nexus::n3_acceptance::{parse_canonical_json, sha256};
use nexus_compute::task_requester::{CancelReason, RequesterMirror, RequesterScope};
use nexus_domain::task::{TaskError, TaskErrorCode, TaskId, TaskView, codec::CanonicalDto};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
const IMAGE: &str = "requester-v1.json";
const RECEIPT: &str = "requester-initialized-v1";
const LOCK: &str = "requester.lock";
fn receipt(m: &fs::Metadata) -> Vec<u8> {
    format!(
        "n3-requester-initialized-v1\nlock={}:{}\n",
        m.dev(),
        m.ino()
    )
    .into_bytes()
}
/// Cloneable transaction handle; all processes serialize through one stable inode.
#[derive(Debug, Clone)]
pub struct FileTaskRequesterStore {
    root: PathBuf,
    device: u64,
    inode: u64,
    initializing: bool,
}
impl FileTaskRequesterStore {
    /// Only a newly created root can initialize. An existing empty/partial root
    /// requires reconciliation and never silently resets lost mirror/outbox state.
    pub fn open(root: &Path) -> Result<Self, TaskError> {
        for p in root
            .parent()
            .ok_or_else(|| disk::corrupt("requester root lacks parent"))?
            .ancestors()
        {
            let m = fs::symlink_metadata(p).map_err(disk::io)?;
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err(disk::corrupt("requester parent is linked/non-directory"));
            }
        }
        let fresh = match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(disk::io(e)),
        };
        disk::check_directory(root)?;
        let root = fs::canonicalize(root).map_err(disk::io)?;
        let m = fs::symlink_metadata(&root).map_err(disk::io)?;
        let mut store = Self {
            root,
            device: m.dev(),
            inode: m.ino(),
            initializing: fresh,
        };
        for parent in store.root.ancestors().skip(1) {
            disk::sync(parent)?;
        }
        if fresh {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(store.root.join(LOCK))
                .map_err(disk::io)?;
            f.write_all(b"n3-requester-lock-v1\n").map_err(disk::io)?;
            f.sync_all().map_err(disk::io)?;
            disk::sync(&store.root)?;
            let _lease = store.lock()?;
            store.save(&[], &mut |_| Ok(()))?;
            disk::atomic(
                &store.root,
                RECEIPT,
                &receipt(&_lease.metadata().map_err(disk::io)?),
            )?;
            store.initializing = false;
        }
        let _lease = store.lock()?;
        store.load()?;
        Ok(store)
    }
    /// The principal/provider scope is supplied by authenticated composition code.
    pub fn receive(
        &self,
        view: TaskView,
        scope: RequesterScope<'_>,
    ) -> Result<TaskView, TaskError> {
        self.transact(&mut |_| Ok(()), |mirrors| {
            if let Some(m) = mirrors
                .iter_mut()
                .find(|m| authority_key(m) == (scope.provider, &view.task_id))
            {
                m.receive(view, scope, sha256)?;
                Ok(m.view())
            } else {
                let m = RequesterMirror::new(view, scope, sha256)?;
                let v = m.view();
                mirrors.push(m);
                Ok(v)
            }
        })
    }
    pub fn read(&self, id: &TaskId, scope: RequesterScope<'_>) -> Result<TaskView, TaskError> {
        let _lease = self.lock()?;
        let mirrors = self.load()?;
        let m = find(&mirrors, id, scope.provider)?;
        m.authorize_scope(scope)?;
        Ok(m.view())
    }
    pub fn disconnected(
        &self,
        id: &TaskId,
        scope: RequesterScope<'_>,
    ) -> Result<TaskView, TaskError> {
        self.transact(&mut |_| Ok(()), |mirrors| {
            let m = find_mut(mirrors, id, scope.provider)?;
            m.authorize_scope(scope)?;
            m.disconnected();
            Ok(m.view())
        })
    }
    /// Returning Queued requires file and directory fsync. An ambiguous write
    /// returns PersistenceFailed; retry reloads durable state without a new Submit.
    pub fn queue_cancel(
        &self,
        id: &TaskId,
        scope: RequesterScope<'_>,
        reason: CancelReason,
        at_unix: u64,
    ) -> Result<TaskView, TaskError> {
        self.queue_with(id, scope, reason, at_unix, &mut |_| Ok(()))
    }
    fn queue_with(
        &self,
        id: &TaskId,
        scope: RequesterScope<'_>,
        reason: CancelReason,
        at_unix: u64,
        boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<TaskView, TaskError> {
        self.transact(boundary, |mirrors| {
            let m = find_mut(mirrors, id, scope.provider)?;
            m.queue_cancel(scope, reason, at_unix)?;
            Ok(m.view())
        })
    }
    /// Call only after a scoped, durable provider response. Ack is delivery,
    /// never authority to assign cancellation=Confirmed or a terminal outcome.
    pub fn settle_cancel(
        &self,
        id: &TaskId,
        scope: RequesterScope<'_>,
        response_task_id: &TaskId,
        rejection: Option<TaskError>,
    ) -> Result<TaskView, TaskError> {
        self.transact(&mut |_| Ok(()), |mirrors| {
            let m = find_mut(mirrors, id, scope.provider)?;
            m.settle_cancel(scope, response_task_id, rejection)?;
            Ok(m.view())
        })
    }
    /// Scoped retry inventory contains only cancels, never task submissions.
    pub fn pending(&self, scope: RequesterScope<'_>) -> Result<Vec<TaskView>, TaskError> {
        let _lease = self.lock()?;
        Ok(self
            .load()?
            .iter()
            .filter(|m| m.cancel_pending() && m.authorize_scope(scope).is_ok())
            .map(RequesterMirror::view)
            .collect())
    }
    fn transact<R>(
        &self,
        boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
        operation: impl FnOnce(&mut Vec<RequesterMirror>) -> Result<R, TaskError>,
    ) -> Result<R, TaskError> {
        let lease = self.lock()?;
        let mut mirrors = self.load()?;
        let before = mirrors.clone();
        let result = operation(&mut mirrors)?;
        self.check_lock(&lease)?;
        if before != mirrors {
            self.save(&mirrors, boundary)?;
        }
        self.check_lock(&lease)?;
        Ok(result)
    }
    fn lock(&self) -> Result<File, TaskError> {
        let f = disk::file(&self.root.join(LOCK), true)?;
        unsafe extern "C" {
            fn flock(fd: std::ffi::c_int, op: std::ffi::c_int) -> std::ffi::c_int;
        }
        loop {
            // SAFETY: live owned fd; LOCK_EX takes no pointers and retains none.
            if unsafe { flock(f.as_raw_fd(), 2) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(disk::io(e));
            }
        }
        self.check_lock(&f)?;
        Ok(f)
    }
    fn check_lock(&self, f: &File) -> Result<(), TaskError> {
        disk::check_directory(&self.root)?;
        let root = fs::symlink_metadata(&self.root).map_err(disk::io)?;
        let actual = disk::file(&self.root.join(LOCK), false)?
            .metadata()
            .map_err(disk::io)?;
        let owned = f.metadata().map_err(disk::io)?;
        if root.dev() != self.device
            || root.ino() != self.inode
            || actual.dev() != owned.dev()
            || actual.ino() != owned.ino()
        {
            return Err(disk::corrupt("requester authority/lock inode changed"));
        }
        if !self.initializing && disk::read(&self.root.join(RECEIPT), 128)? != receipt(&owned) {
            return Err(disk::corrupt(
                "requester stable lock differs from initialization receipt",
            ));
        }
        Ok(())
    }
    fn load(&self) -> Result<Vec<RequesterMirror>, TaskError> {
        if disk::read(&self.root.join(RECEIPT), 128)?
            != receipt(
                &disk::file(&self.root.join(LOCK), false)?
                    .metadata()
                    .map_err(disk::io)?,
            )
        {
            return Err(disk::corrupt("requester initialization receipt differs"));
        }
        let p = disk::load(&self.root.join(IMAGE))?;
        if p.as_object().map(|m| m.len()) != Some(2) || p["schema_version"] != 1 {
            return Err(disk::corrupt("requester schema differs"));
        }
        let raw = p["mirrors"]
            .as_array()
            .ok_or_else(|| disk::corrupt("requester mirrors not array"))?;
        let mut mirrors = Vec::new();
        for v in raw {
            mirrors.push(
                RequesterMirror::from_value(parse_canonical_json(
                    &serde_json::to_vec(v).map_err(|e| disk::corrupt(e.to_string()))?,
                )?)
                .map_err(|e| disk::corrupt(e.to_string()))?,
            );
        }
        validate(&mirrors)?;
        Ok(mirrors)
    }
    fn save(
        &self,
        mirrors: &[RequesterMirror],
        boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<(), TaskError> {
        validate(mirrors)?;
        let raw: Vec<Value> = mirrors
            .iter()
            .map(|m| {
                serde_json::from_slice(&m.to_value().canonical_bytes())
                    .map_err(|e| disk::corrupt(e.to_string()))
            })
            .collect::<Result<_, _>>()?;
        let payload = json!({"schema_version":1,"mirrors":raw});
        let bytes = disk::canonical(
            &json!({"payload":payload,"checksum":sha256(&disk::canonical(&payload)?).as_str()}),
        )?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(TaskError::new(
                TaskErrorCode::CapacityUnavailable,
                "requester image exceeds 8 MiB",
                false,
            ));
        }
        disk::atomic_with(&self.root, IMAGE, &bytes, boundary)
    }
}
fn validate(mirrors: &[RequesterMirror]) -> Result<(), TaskError> {
    let mut ids = BTreeSet::new();
    for m in mirrors {
        m.validate(sha256)
            .map_err(|e| disk::corrupt(e.to_string()))?;
        if !ids.insert(authority_key(m)) {
            return Err(disk::corrupt("duplicate requester Provider/TaskId"));
        }
    }
    Ok(())
}
fn authority_key(m: &RequesterMirror) -> (&str, &TaskId) {
    (
        &m.provider_view().accepted_contract.request.provider,
        &m.provider_view().task_id,
    )
}
fn find<'a>(
    mirrors: &'a [RequesterMirror],
    id: &TaskId,
    provider: &str,
) -> Result<&'a RequesterMirror, TaskError> {
    mirrors
        .iter()
        .find(|m| authority_key(m) == (provider, id))
        .ok_or_else(|| TaskError::invalid("requester TaskId not found"))
}
fn find_mut<'a>(
    mirrors: &'a mut [RequesterMirror],
    id: &TaskId,
    provider: &str,
) -> Result<&'a mut RequesterMirror, TaskError> {
    mirrors
        .iter_mut()
        .find(|m| authority_key(m) == (provider, id))
        .ok_or_else(|| TaskError::invalid("requester TaskId not found"))
}
#[cfg(test)]
#[path = "task_requester_store_tests.rs"]
mod tests;
