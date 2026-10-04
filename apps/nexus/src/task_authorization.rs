//! N3 composition-root authorization; current grants and durable refusal audit.
use crate::{n2_identity, n2_store::N2Store};
use nexus_auth::{AuthRequest, Principal};
use nexus_domain::task::{AcceptedContract, TaskError, TaskErrorCode};
use nexus_domain::{
    AuthorizationDecision, ResourceName, ResourceOperation, ResourceRef, WorkspaceId,
};
use std::path::Path;

fn persistence(reason: String) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, reason, true)
}
pub fn authenticated_principal(node_dir: &Path) -> Result<String, TaskError> {
    private_store_root(node_dir)?;
    let store = N2Store::open(node_dir).map_err(persistence)?;
    #[cfg(unix)]
    let before = private_identity(&store, true)?;
    let (_, principal) = n2_identity::ensure_auth_identity(&store).map_err(persistence)?;
    #[cfg(unix)]
    {
        let after = private_identity(&store, false)?
            .ok_or_else(|| persistence("N3 identity record missing".into()))?;
        if before.is_some_and(|previous| previous != after) {
            return Err(persistence("N3 identity inode changed during load".into()));
        }
    }
    Ok(principal.0)
}
/// Adapter refusal is distinct from the grant table's actual Allow/Deny audit.
pub fn audit_refusal(
    node_dir: &Path,
    principal: &str,
    workspace: &str,
    task_id: Option<&str>,
    reason: &str,
) -> Result<(), TaskError> {
    private_store_root(node_dir)?;
    let store = N2Store::open(node_dir).map_err(persistence)?;
    let event = serde_json::json!({"event":"n3.adapter_refusal","principal":principal,"workspace":workspace,"task_id":task_id,"reason":reason,"at_unix":crate::n2_store::now_unix_pub()});
    store
        .kv()
        .journal_append(&serde_json::to_vec(&event).map_err(|e| persistence(e.to_string()))?)
        .map(|_| ())
        .map_err(|e| persistence(format!("N3 refusal audit: {e}")))
}
pub fn authorize_use(
    node_dir: &Path,
    principal: &str,
    workspace: &str,
    resource: &str,
) -> Result<(), TaskError> {
    let name = ResourceName::new(resource).map_err(|e| TaskError::invalid(e.to_string()))?;
    let reference = ResourceRef::new(WorkspaceId::new(workspace), name);
    private_store_root(node_dir)?;
    let store = N2Store::open(node_dir).map_err(persistence)?;
    let table = store.load_grant_table().map_err(persistence)?;
    let outcome = table.authorize(
        &AuthRequest {
            workspace: reference.workspace.clone(),
            resource: reference,
            principal: Principal(principal.to_owned()),
            operation: ResourceOperation::Use,
        },
        crate::n2_store::now_unix_pub(),
        &mut store.audit_sink(),
    );
    if !outcome.audit_written {
        return Err(persistence(
            "N3 authorization audit was not persisted".into(),
        ));
    }
    match outcome.decision {
        AuthorizationDecision::Allow => Ok(()),
        AuthorizationDecision::Deny(reason) => Err(TaskError::new(
            TaskErrorCode::AuthDenied,
            format!("current Use grant denied: {reason:?}"),
            false,
        )),
    }
}
pub fn authorize_contract(
    node_dir: &Path,
    principal: &str,
    workspace: &str,
    provider: &str,
    contract: &AcceptedContract,
    task_id: &str,
) -> Result<(), TaskError> {
    if principal != contract.authenticated_principal
        || workspace != contract.request.workspace
        || provider != contract.request.provider
    {
        let reason =
            "authenticated principal, configured workspace or provider differs from accepted Task";
        audit_refusal(node_dir, principal, workspace, Some(task_id), reason)?;
        return Err(TaskError::new(TaskErrorCode::AuthDenied, reason, false));
    }
    authorize_use(node_dir, principal, workspace, &contract.request.resource)
}

/// N3 adds credential-directory checks without changing v0's identity protocol.
fn private_store_root(node_dir: &Path) -> Result<(), TaskError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let root = std::fs::symlink_metadata(node_dir).map_err(|e| persistence(e.to_string()))?;
        if !root.is_dir() || root.file_type().is_symlink() || root.permissions().mode() & 0o077 != 0
        {
            return Err(persistence(
                "N3 config directory must be private and real".into(),
            ));
        }
        let n2 = node_dir.join("n2");
        match std::fs::DirBuilder::new().mode(0o700).create(&n2) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(persistence(e.to_string())),
        }
        let metadata = std::fs::symlink_metadata(&n2).map_err(|e| persistence(e.to_string()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(persistence(
                "N3 N2 credential directory must be private and real".into(),
            ));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn private_identity(store: &N2Store, allow_missing: bool) -> Result<Option<(u64, u64)>, TaskError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let name = nexus_storage::FileKvStore::file_name_for("n2/auth-identity")
        .ok_or_else(|| persistence("invalid identity key".into()))?;
    let path = store.kv().dir().join(name);
    // Linux/macOS native O_NOFOLLOW + O_NONBLOCK; unsupported Unix rejects explicitly.
    #[cfg(target_os = "linux")]
    let flags = 0x20000 | 0x800;
    #[cfg(target_os = "macos")]
    let flags = 0x100 | 0x4;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(persistence(
        "private N3 credential reader unsupported on this Unix platform".into(),
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if allow_missing && e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(persistence(format!("N3 identity metadata: {e}"))),
        };
        let fd = file.metadata().map_err(|e| persistence(e.to_string()))?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| persistence(e.to_string()))?;
        if !fd.is_file()
            || fd.nlink() != 1
            || fd.permissions().mode() & 0o777 != 0o600
            || metadata.file_type().is_symlink()
            || metadata.dev() != fd.dev()
            || metadata.ino() != fd.ino()
        {
            return Err(persistence(
                "N3 identity must be a private regular bound file".into(),
            ));
        }
        Ok(Some((fd.dev(), fd.ino())))
    }
}
