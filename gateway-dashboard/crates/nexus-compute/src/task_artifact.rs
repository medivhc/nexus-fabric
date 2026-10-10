//! Portable registration facts. Only TaskOwner commits delivery/outcome.
use crate::task::record_codec;
use nexus_domain::task::{
    codec::{CanonicalDto, DigestFn, Value},
    *,
};
use std::collections::{BTreeMap, BTreeSet};

/// Provider-internal evidence of durably registered retained log bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredLog {
    pub stream: String,
    pub size_bytes: u64,
    pub content_sha256: Sha256Digest,
    pub truncated: bool,
}
record_codec!(RegisteredLog {
    stream: String,
    size_bytes: u64,
    content_sha256: Sha256Digest,
    truncated: bool
});

/// IO adapters must additionally prove bytes, durable catalog and access path.
/// A storage_ref or publication flag alone is not that proof.
pub fn validate_registration(
    view: &TaskView,
    records: &[ArtifactRecord],
    logs: &[RegisteredLog],
    hash: DigestFn,
) -> Result<(), TaskError> {
    let contract = &view.accepted_contract;
    let env = hash(&contract.environment_evidence.to_value().canonical_bytes());
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for record in records {
        record.validate()?;
        total = total
            .checked_add(record.size_bytes)
            .ok_or_else(|| TaskError::invalid("Artifact size overflow"))?;
        if record.task_id != view.task_id
            || record.snapshot_id != contract.request.input_snapshot.snapshot_id
            || record.environment_digest != env
            || record.producer_node != contract.request.provider
            || record.workspace != contract.request.workspace
            || record.owner_principal != contract.authenticated_principal
            || record.created_at_unix < contract.accepted_at_unix
            || record.publication_state != PublicationState::Published
            || record.size_bytes > contract.request.limits.storage_bytes
            || !contract
                .request
                .outputs
                .iter()
                .any(|o| o.path == record.path)
            || !ids.insert(record.artifact_id.clone())
            || !paths.insert(record.path.clone())
        {
            return Err(TaskError::invalid(
                "Artifact registration differs from accepted Task",
            ));
        }
    }
    if total > contract.request.limits.storage_bytes {
        return Err(TaskError::invalid(
            "registered outputs exceed accepted storage limit",
        ));
    }
    if contract
        .request
        .outputs
        .iter()
        .any(|o| o.required && !paths.contains(&o.path))
    {
        return Err(TaskError::invalid("required Artifact is not registered"));
    }
    if logs.len() != 2
        || logs[0].stream != "stdout"
        || logs[1].stream != "stderr"
        || logs[0]
            .size_bytes
            .checked_add(logs[1].size_bytes)
            .is_none_or(|n| n > contract.request.limits.log_bytes)
    {
        return Err(TaskError::invalid(
            "both bounded log streams must be registered",
        ));
    }
    Ok(())
}
