//! Linux provider Artifact catalog. TaskOwner alone finalizes delivery/outcome.
//! Not a product route: the service must supply current grant checks.
use crate::{artifact_fs as disk, task_store::FileTaskAcceptanceStore};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_compute::{
    task::{AcceptanceLedger, TaskOwner},
    task_artifact::{RegisteredLog, validate_registration},
    task_runtime::*,
};
use nexus_domain::task::{
    codec::{CanonicalDto, Value},
    *,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const AUTHORITY_RECEIPT: &[u8] =
    b"n3-acceptance-initialized-v1\nruntime-v1-required\nartifacts-v1-required\n";
const IMAGE: &str = "artifacts-v1.json";
const RECEIPT: &str = "artifacts-initialized-v1";
const RECEIPT_BYTES: &[u8] = b"n3-artifacts-initialized-v1\n";
const CONTENT: &str = "artifact-content-sha256-v1";
#[path = "task_artifacts_catalog.rs"]
mod catalog;
pub(crate) use catalog::validate_runtime;
use catalog::{get, initialize, integrity, load, now, publication, publication_mut, put, save};
macro_rules! codec {
    ($name:ident {$($field:ident:$ty:ty),+}) => {
        impl CanonicalDto for $name {
            fn to_value(&self)->Value { Value::Object(BTreeMap::from([$( (stringify!($field).into(),self.$field.to_value()) ),+])) }
            fn from_value(v:Value)->Result<Self,TaskError> { let Value::Object(mut f)=v else { return Err(disk::corrupt("invalid Artifact metadata")); }; let r=Self { $( $field:<$ty>::from_value(f.remove(stringify!($field)).ok_or_else(||disk::corrupt(concat!("missing ",stringify!($field))))?)? ),+ }; if !f.is_empty() { return Err(disk::corrupt("unknown Artifact field")); } Ok(r) }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Publication {
    task_id: TaskId,
    contract_digest: Sha256Digest,
    artifacts: Vec<ArtifactRecord>,
    logs: Vec<RegisteredLog>,
    logs_published: bool,
    missing: Vec<String>,
}
codec!(Publication {task_id:TaskId,contract_digest:Sha256Digest,artifacts:Vec<ArtifactRecord>,logs:Vec<RegisteredLog>,logs_published:bool,missing:Vec<String>});
#[derive(Clone, Debug, PartialEq, Eq)]
struct Image {
    schema_version: u64,
    publications: Vec<Publication>,
}
codec!(Image {schema_version:u64,publications:Vec<Publication>});

/// Identity is supplied by an authenticated service, never decoded from storage_ref.
#[derive(Clone, Copy)]
pub struct ArtifactAccess<'a> {
    pub principal: &'a str,
    pub workspace: &'a str,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ArtifactPage {
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
}
/// No delete API: pending/active/retained references remain roots. GC and
/// retention policy integration await the full service recovery batch.
pub struct FileTaskArtifacts {
    store: FileTaskAcceptanceStore,
    root: PathBuf,
}
impl FileTaskArtifacts {
    pub fn open(root: &Path) -> Result<Self, TaskError> {
        let store = FileTaskAcceptanceStore::open(root)?;
        let root = root.canonicalize().map_err(disk::io)?;
        store.with_locked_ledger(initialize)?;
        Ok(Self { store, root })
    }
    /// Provider-internal publication from confirmed sealed executor evidence.
    /// This never executes the command. Retry repairs ambiguous durable writes.
    pub fn publish(&self, id: &TaskId, retention_seconds: u64) -> Result<RuntimeState, TaskError> {
        self.publish_with(id, retention_seconds, &mut |_| Ok(()))
    }
    fn publish_with(
        &self,
        id: &TaskId,
        retention_seconds: u64,
        boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<RuntimeState, TaskError> {
        let owner = TaskOwner::new(self.store.clone(), sha256, new_task_id);
        let state = owner.runtime(id)?;
        if state.view.outcome != TaskOutcome::Unfinished {
            // Existing terminal outcome remains immutable, including a deadline.
            return Ok(state);
        }
        if state.view.execution.state == ExecutionState::Exited
            && state.view.observation == Observation::Confirmed
            && now()? >= state.view.accepted_contract.delivery_deadline_unix
        {
            return record(
                &owner,
                id,
                RuntimeAction::DeliveryDeadline { now_unix: now()? },
            );
        }
        let source = crate::task_executor::sealed_results(&self.root, &state)?;
        let work = (|| {
            self.store.with_locked_ledger(|root, ledger| {
                let mut image = load(root, ledger)?
                    .ok_or_else(|| disk::corrupt("missing Artifact authority"))?;
                if !image.publications.iter().any(|p| &p.task_id == id) {
                    let now = now()?;
                    let retain = now
                        .checked_add(retention_seconds)
                        .filter(|v| *v <= MAX_INTEGER)
                        .ok_or_else(|| TaskError::invalid("Artifact retention overflow"))?;
                    let c = &state.view.accepted_contract;
                    let mut records = Vec::new();
                    let mut missing = Vec::new();
                    for (spec, bytes) in &source.outputs {
                        if let Some(bytes) = bytes {
                            let digest = sha256(bytes);
                            let identity = Value::Array(vec![
                                id.to_value(),
                                spec.path.to_value(),
                                digest.to_value(),
                            ]);
                            records.push(ArtifactRecord {
                                schema_version: 1,
                                artifact_id: ArtifactId::new(format!(
                                    "artifact:{}",
                                    &sha256(&identity.canonical_bytes()).as_str()[7..]
                                ))?,
                                task_id: id.clone(),
                                snapshot_id: c.request.input_snapshot.snapshot_id.clone(),
                                environment_digest: sha256(
                                    &c.environment_evidence.to_value().canonical_bytes(),
                                ),
                                producer_node: c.request.provider.clone(),
                                workspace: c.request.workspace.clone(),
                                owner_principal: c.authenticated_principal.clone(),
                                path: spec.path.clone(),
                                size_bytes: bytes.len() as u64,
                                content_sha256: digest.clone(),
                                storage_ref: format!("artifact-v1:{}", &digest.as_str()[7..]),
                                created_at_unix: now,
                                retain_until_unix: retain,
                                publication_state: PublicationState::Pending,
                            });
                        } else if spec.required {
                            missing.push(spec.path.clone());
                        }
                    }
                    image.publications.push(Publication {
                        task_id: id.clone(),
                        contract_digest: state.view.contract_digest.clone(),
                        artifacts: records,
                        logs: source.logs.iter().map(|(l, _)| l.clone()).collect(),
                        logs_published: false,
                        missing,
                    });
                    save(root, &image, ledger)?;
                }
                Ok(())
            })?;
            boundary("after_manifest")?;
            // Content and registration commit under the same acceptance/GC lock.
            for (spec, bytes) in &source.outputs {
                let Some(bytes) = bytes else {
                    continue;
                };
                self.store.with_locked_ledger(|root, ledger| {
                    let mut image = load(root, ledger)?
                        .ok_or_else(|| disk::corrupt("missing Artifact image"))?;
                    let p = publication_mut(&mut image, id)?;
                    let record = p
                        .artifacts
                        .iter_mut()
                        .find(|r| r.path == spec.path)
                        .ok_or_else(|| {
                            disk::corrupt("staged Artifact disappeared from manifest")
                        })?;
                    if record.content_sha256 != sha256(bytes)
                        || record.size_bytes != bytes.len() as u64
                    {
                        return Err(integrity(
                            "staged Artifact changed after publication intent",
                        ));
                    }
                    put(root, &record.content_sha256, bytes)?;
                    boundary("after_content")?;
                    record.publication_state = PublicationState::Published;
                    save(root, &image, ledger)?;
                    boundary("after_registration")
                })?;
            }
            self.store.with_locked_ledger(|root, ledger| {
                let mut image =
                    load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact image"))?;
                let p = publication_mut(&mut image, id)?;
                if p.logs
                    != source
                        .logs
                        .iter()
                        .map(|(l, _)| l.clone())
                        .collect::<Vec<_>>()
                {
                    return Err(integrity("sealed logs changed after publication intent"));
                }
                for (log, bytes) in &source.logs {
                    put(root, &log.content_sha256, bytes)?;
                }
                boundary("after_log_content")?;
                p.logs_published = true;
                save(root, &image, ledger)
            })?;
            boundary("before_outcome")?;
            let p = self.store.with_locked_ledger(|root, ledger| {
                let image =
                    load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact image"))?;
                Ok(publication(&image, id)?.clone())
            })?;
            let time = now()?;
            if time >= state.view.accepted_contract.delivery_deadline_unix {
                return record(
                    &owner,
                    id,
                    RuntimeAction::DeliveryDeadline { now_unix: time },
                );
            }
            if p.missing.is_empty() {
                record(
                    &owner,
                    id,
                    RuntimeAction::DeliveryReady {
                        artifacts: p.artifacts,
                        logs: p.logs,
                        at_unix: time,
                    },
                )
            } else {
                record(
                    &owner,
                    id,
                    RuntimeAction::ArtifactsMissing { paths: p.missing },
                )
            }
        })();
        if let Err(error) = &work {
            if error.retryable
                && matches!(
                    error.code,
                    TaskErrorCode::PersistenceFailed
                        | TaskErrorCode::ArtifactUnavailable
                        | TaskErrorCode::ProviderUnreachable
                        | TaskErrorCode::CapacityUnavailable
                )
                && owner.runtime(id)?.view.outcome == TaskOutcome::Unfinished
            {
                record(
                    &owner,
                    id,
                    RuntimeAction::DeliveryPending {
                        error: error.clone(),
                    },
                )?;
            }
        }
        work
    }
    /// Every call requires a fresh authorization check, even for cached pages.
    /// Callback runs outside the storage lock and may call other service methods.
    pub fn get(
        &self,
        id: &ArtifactId,
        access: ArtifactAccess<'_>,
        offset: u64,
        max_bytes: usize,
        authorize: &mut dyn FnMut(&ArtifactRecord) -> Result<(), TaskError>,
    ) -> Result<ArtifactPage, TaskError> {
        bounds(max_bytes)?;
        let record = self.store.with_locked_ledger(|root, ledger| {
            let image =
                load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact catalog"))?;
            image
                .publications
                .iter()
                .flat_map(|p| &p.artifacts)
                .find(|r| &r.artifact_id == id)
                .cloned()
                .ok_or_else(|| {
                    TaskError::new(
                        TaskErrorCode::ArtifactUnavailable,
                        "unknown Artifact",
                        false,
                    )
                })
        })?;
        let grant = self
            .identity(access, &record.owner_principal, &record.workspace)
            .and_then(|()| authorize(&record));
        if let Err(error) = grant {
            return self.deny(Some(&record.task_id), access, error);
        }
        self.store.with_locked_ledger(|root, ledger| {
            let image =
                load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact catalog"))?;
            let p = publication(&image, &record.task_id)?;
            if !p.artifacts.contains(&record)
                || record.publication_state != PublicationState::Published
            {
                return Err(TaskError::new(
                    TaskErrorCode::ArtifactUnavailable,
                    "Artifact is not Published",
                    true,
                ));
            }
            page(
                get(root, &record.content_sha256, record.size_bytes)?,
                offset,
                max_bytes,
            )
        })
    }
    pub fn list(
        &self,
        id: &TaskId,
        access: ArtifactAccess<'_>,
        authorize: &mut dyn FnMut(&AcceptedContract) -> Result<(), TaskError>,
    ) -> Result<Vec<ArtifactRecord>, TaskError> {
        let state = TaskOwner::new(self.store.clone(), sha256, new_task_id).runtime(id)?;
        let c = &state.view.accepted_contract;
        if let Err(e) = self
            .identity(access, &c.authenticated_principal, &c.request.workspace)
            .and_then(|()| authorize(c))
        {
            return self.deny(Some(id), access, e);
        }
        self.store.with_locked_ledger(|root, ledger| {
            let image =
                load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact catalog"))?;
            Ok(image
                .publications
                .iter()
                .find(|p| &p.task_id == id)
                .map(|p| p.artifacts.clone())
                .unwrap_or_default())
        })
    }
    /// Composition-root routing only; validates authority without masking a
    /// missing published catalog as ordinary not-yet-registered logs.
    pub(crate) fn logs_registered(&self, id: &TaskId) -> Result<bool, TaskError> {
        self.store.with_locked_ledger(|root, ledger| {
            let image =
                load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact catalog"))?;
            Ok(image
                .publications
                .iter()
                .find(|p| &p.task_id == id)
                .is_some_and(|p| p.logs_published))
        })
    }
    /// Published immutable logs have the same two independent byte offsets.
    pub fn logs(
        &self,
        id: &TaskId,
        access: ArtifactAccess<'_>,
        stream: crate::task_executor::LogStream,
        offset: u64,
        max_bytes: usize,
        authorize: &mut dyn FnMut(&AcceptedContract) -> Result<(), TaskError>,
    ) -> Result<crate::task_executor::LogPage, TaskError> {
        bounds(max_bytes)?;
        let state = TaskOwner::new(self.store.clone(), sha256, new_task_id).runtime(id)?;
        let c = &state.view.accepted_contract;
        if let Err(e) = self
            .identity(access, &c.authenticated_principal, &c.request.workspace)
            .and_then(|()| authorize(c))
        {
            return self.deny(Some(id), access, e);
        }
        self.store.with_locked_ledger(|root, ledger| {
            let image =
                load(root, ledger)?.ok_or_else(|| disk::corrupt("missing Artifact catalog"))?;
            let p = publication(&image, id)?;
            if !p.logs_published {
                return Err(TaskError::new(
                    TaskErrorCode::ArtifactUnavailable,
                    "logs not registered",
                    true,
                ));
            }
            let log = &p.logs[match stream {
                crate::task_executor::LogStream::Stdout => 0,
                crate::task_executor::LogStream::Stderr => 1,
            }];
            let page = page(
                get(root, &log.content_sha256, log.size_bytes)?,
                offset,
                max_bytes,
            )?;
            Ok(crate::task_executor::LogPage {
                bytes: page.bytes,
                next_offset: page.next_offset,
                eof: page.eof,
                truncated: log.truncated,
            })
        })
    }
    fn identity(
        &self,
        access: ArtifactAccess<'_>,
        principal: &str,
        workspace: &str,
    ) -> Result<(), TaskError> {
        if access.principal == principal && access.workspace == workspace {
            Ok(())
        } else {
            Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "Artifact principal/workspace scope denied",
                false,
            ))
        }
    }
    fn deny<T>(
        &self,
        id: Option<&TaskId>,
        access: ArtifactAccess<'_>,
        error: TaskError,
    ) -> Result<T, TaskError> {
        self.store.with_locked_ledger(|root,_| {
            let dir=root.join("artifact-audit-v1");disk::directory(&dir)?;
            let audit=nexus_storage::FileKvStore::open(&dir).map_err(|e|disk::corrupt(e.to_string()))?;
            let payload=disk::canonical(&json!({"schema_version":1,"operation":"ArtifactReadDenied","task_id":id.map(TaskId::as_str),"principal":access.principal,"workspace":access.workspace,"error":error.code.as_str(),"at_unix":now()?}))?;
            audit.journal_append(&payload).map_err(|e| TaskError::new(TaskErrorCode::PersistenceFailed,format!("Artifact denial audit: {e}"),true))?;
            Ok(())
        })?;
        Err(error)
    }
}
fn bounds(n: usize) -> Result<(), TaskError> {
    if n == 0 || n > 65536 {
        Err(TaskError::invalid("Artifact page must be 1..65536 bytes"))
    } else {
        Ok(())
    }
}
fn page(bytes: Vec<u8>, offset: u64, n: usize) -> Result<ArtifactPage, TaskError> {
    if offset > bytes.len() as u64 {
        return Err(TaskError::invalid("Artifact offset past end"));
    }
    let start = offset as usize;
    let end = start.saturating_add(n).min(bytes.len());
    Ok(ArtifactPage {
        bytes: bytes[start..end].to_vec(),
        next_offset: end as u64,
        eof: end == bytes.len(),
    })
}
fn record(
    owner: &TaskOwner<FileTaskAcceptanceStore>,
    id: &TaskId,
    action: RuntimeAction,
) -> Result<RuntimeState, TaskError> {
    for _ in 0..16 {
        let state = owner.runtime(id)?;
        if state.view.outcome != TaskOutcome::Unfinished {
            return Ok(state);
        }
        let sequence = state
            .view
            .last_event_seq
            .checked_add(1)
            .ok_or_else(|| disk::corrupt("event sequence overflow"))?;
        match owner.record_event(
            id,
            RuntimeEvent {
                sequence,
                action: action.clone(),
            },
        ) {
            Ok(update) => return Ok(update.state),
            Err(e)
                if e.code == TaskErrorCode::InvalidRequest
                    && owner.runtime(id)?.view.last_event_seq != state.view.last_event_seq => {}
            Err(e) => return Err(e),
        }
    }
    Err(TaskError::new(
        TaskErrorCode::PersistenceFailed,
        "runtime changed too frequently",
        true,
    ))
}
#[cfg(test)]
#[path = "task_artifacts_tests.rs"]
mod tests;
