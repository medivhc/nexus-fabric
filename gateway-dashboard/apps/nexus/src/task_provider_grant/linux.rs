use super::{Command, Failure, Operation, Result, principal_valid};
use crate::n3_acceptance::{parse_canonical_json, sha256};
use nexus_auth::{Grant, Principal};
use nexus_domain::task::{MAX_INTEGER, TaskErrorCode, TaskId};
use nexus_domain::{ResourceName, ResourceOperation, ResourceRef, WorkspaceId};
use serde_json::{Value, json};
use std::fs;

#[path = "audit.rs"]
mod audit;
#[path = "io.rs"]
mod io;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

struct Scope {
    provider: String,
    workspace: String,
    record: io::Record,
}
impl Scope {
    fn open(roots: &io::Roots) -> Result<Self> {
        let record = io::read(&roots.config.join("task-api.toml"), false)?;
        let text = std::str::from_utf8(&record.bytes)
            .map_err(|_| io::corrupt("task-api must be UTF-8"))?;
        let fields = text
            .parse::<toml::Table>()
            .map_err(|_| io::corrupt("invalid task-api TOML"))?;
        if fields.len() != 2 {
            return Err(io::corrupt(
                "task-api requires exactly provider and workspace",
            ));
        }
        let provider = fields
            .get("provider")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| io::corrupt("task-api provider must be a string"))?
            .to_owned();
        let workspace = fields
            .get("workspace")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| io::corrupt("task-api workspace must be a string"))?
            .to_owned();
        for value in [&provider, &workspace] {
            TaskId::new(value.to_string())
                .map_err(|_| io::corrupt("invalid task-api scope identifier"))?;
        }
        roots.check()?;
        Ok(Self {
            provider,
            workspace,
            record,
        })
    }
    fn value(&self) -> Value {
        json!({"provider":self.provider,"workspace":self.workspace})
    }
    fn check(&self, roots: &io::Roots) -> Result<()> {
        roots.check()?;
        io::check_file(
            &self.record.file,
            &roots.config.join("task-api.toml"),
            false,
        )?;
        let current = io::read(&roots.config.join("task-api.toml"), false)?;
        if current.bytes != self.record.bytes {
            return Err(io::corrupt("configured operator scope changed"));
        }
        Ok(())
    }
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    Ok(
        parse_canonical_json(&serde_json::to_vec(value).map_err(io::persistence)?)
            .map_err(|_| io::corrupt("invalid operator canonical JSON"))?
            .canonical_bytes(),
    )
}
fn strict_json(bytes: &[u8]) -> Result<Value> {
    let canonical = parse_canonical_json(bytes)
        .map_err(|_| io::corrupt("invalid operator JSON"))?
        .canonical_bytes();
    serde_json::from_slice(&canonical).map_err(|_| io::corrupt("invalid operator JSON"))
}
fn grant_filename(reference: &ResourceRef, principal: &Principal) -> Result<String> {
    let key = crate::n2_store::grant_key(reference, principal);
    let name = nexus_storage::FileKvStore::file_name_for(&key)
        .filter(|name| name.len() <= 255)
        .ok_or_else(|| {
            Failure::new(
                TaskErrorCode::InvalidRequest,
                "scoped grant key exceeds the storage filename bound",
                false,
            )
        })?;
    Ok(name)
}
fn decode_grant(bytes: &[u8], name: &str, workspace: &str) -> Result<Grant> {
    let value = strict_json(bytes)?;
    let fields = value
        .as_object()
        .ok_or_else(|| io::corrupt("grant must be an object"))?;
    if fields.len() != 6
        || ![
            "workspace",
            "name",
            "principal",
            "operations",
            "not_after",
            "revoked",
        ]
        .iter()
        .all(|key| fields.contains_key(*key))
    {
        return Err(io::corrupt("grant shape differs from the N2 record"));
    }
    let read_string = |field: &str| {
        value[field]
            .as_str()
            .ok_or_else(|| io::corrupt("grant requires string identity fields"))
    };
    let actual_workspace = read_string("workspace")?;
    if actual_workspace != workspace {
        return Err(io::corrupt(
            "grant workspace differs from its scoped filename",
        ));
    }
    let resource = ResourceName::new(read_string("name")?)
        .map_err(|_| io::corrupt("invalid grant resource"))?;
    let principal = read_string("principal")?;
    if !principal_valid(principal) {
        return Err(io::corrupt("invalid grant principal"));
    }
    let operations = value["operations"]
        .as_array()
        .ok_or_else(|| io::corrupt("grant operations must be an array"))?
        .iter()
        .map(|operation| match operation.as_str() {
            Some("use") => Ok(ResourceOperation::Use),
            Some("manage") => Ok(ResourceOperation::Manage),
            _ => Err(io::corrupt("unknown grant operation")),
        })
        .collect::<Result<Vec<_>>>()?;
    let not_after = match &value["not_after"] {
        Value::Null => None,
        value => Some(
            value
                .as_u64()
                .filter(|v| *v <= MAX_INTEGER)
                .ok_or_else(|| {
                    io::corrupt("grant expiration must be an exact nonnegative integer")
                })?,
        ),
    };
    let grant = Grant {
        resource: ResourceRef::new(WorkspaceId::new(workspace), resource),
        principal: Principal(principal.to_owned()),
        operations,
        not_after,
        revoked: value["revoked"]
            .as_bool()
            .ok_or_else(|| io::corrupt("grant revoked must be boolean"))?,
    };
    if grant_filename(&grant.resource, &grant.principal)? != name {
        return Err(io::corrupt("grant identities differ from its filename"));
    }
    Ok(grant)
}
fn grant_value(grant: &Grant) -> Value {
    json!({"resource":grant.resource.name.as_str(),"principal":grant.principal.0,
        "operations":grant.operations.iter().map(ResourceOperation::as_str).collect::<Vec<_>>(),
        "not_after":grant.not_after,"revoked":grant.revoked})
}
fn list(command: &Command, roots: &io::Roots, scope: &Scope) -> Result<Value> {
    let scope_header =
        nexus_storage::FileKvStore::file_name_for(&format!("n2/grant/{}", scope.workspace))
            .ok_or_else(|| io::corrupt("invalid scoped grant header"))?;
    let mut grants = Vec::new();
    for entry in fs::read_dir(&roots.n2).map_err(io::persistence)? {
        let entry = entry.map_err(io::persistence)?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        // Workspace identifiers may contain '/'. Resource names and the fixed
        // principal grammar cannot, so the final two encoded '/' delimiters
        // separate the entire Workspace header without a prefix collision.
        // Decide scope before opening any record, including other-scope FIFOs.
        let Some((head_and_resource, _)) = filename.rsplit_once("%2F") else {
            continue;
        };
        let Some((header, resource)) = head_and_resource.rsplit_once("%2F") else {
            continue;
        };
        if header != scope_header
            || command
                .resource
                .as_ref()
                .is_some_and(|selected| selected != resource)
        {
            continue;
        }
        if grants.len() == 4096 {
            return Err(io::capacity(
                "scoped grant listing exceeds 4096 records",
                false,
            ));
        }
        let record = io::read(&entry.path(), false)?;
        let grant = decode_grant(&record.bytes, filename, &scope.workspace)?;
        grants.push(grant);
    }
    grants.sort_by(|a, b| {
        (a.resource.name.as_str(), &a.principal.0).cmp(&(b.resource.name.as_str(), &b.principal.0))
    });
    scope.check(roots)?;
    let value = json!({"schema_version":1,"verdict":"PASS","command":"task-provider grant list",
        "scope":scope.value(),"grants":grants.iter().map(grant_value).collect::<Vec<_>>()});
    if serde_json::to_vec(&value).map_err(io::persistence)?.len() > 2 * 1024 * 1024 {
        return Err(io::capacity("scoped grant response exceeds 2 MiB", false));
    }
    Ok(value)
}
pub(super) fn execute(command: &Command) -> Result<Value> {
    let roots = io::Roots::open(&command.config)?;
    let scope = Scope::open(&roots)?;
    if command.operation == Operation::List {
        return list(command, &roots, &scope);
    }
    let identity_name = nexus_storage::FileKvStore::file_name_for("n2/auth-identity")
        .ok_or_else(|| io::corrupt("invalid identity key"))?;
    let identity_path = roots.n2.join(identity_name);
    let identity = io::read(&identity_path, true)?;
    let actor = crate::n2_identity::principal_from_existing_bytes(&identity.bytes)
        .map_err(|_| io::corrupt("existing operator identity is invalid"))?;
    let principal = if command.self_target {
        actor.clone()
    } else {
        Principal(
            command
                .principal
                .clone()
                .ok_or_else(|| io::corrupt("missing target principal"))?,
        )
    };
    let resource = ResourceName::new(
        command
            .resource
            .as_deref()
            .ok_or_else(|| io::corrupt("missing resource"))?,
    )
    .map_err(|_| io::corrupt("invalid resource"))?;
    let reference = ResourceRef::new(WorkspaceId::new(&scope.workspace), resource);
    let filename = grant_filename(&reference, &principal)?;
    let path = roots.n2.join(&filename);
    let lease = io::Lease::acquire(&roots)?;
    let check = || -> Result<()> {
        lease.check(&roots)?;
        scope.check(&roots)?;
        io::check_file(&identity.file, &identity_path, true)?;
        if io::read(&identity_path, true)?.bytes != identity.bytes {
            return Err(io::corrupt("operator identity changed"));
        }
        Ok(())
    };
    check()?;
    let mut journal = audit::Journal::load(&roots, &scope.value())?;
    let before = io::read_optional(&path, io::RECORD_LIMIT, false)?;
    let existing = before
        .as_ref()
        .map(|r| decode_grant(&r.bytes, &filename, &scope.workspace))
        .transpose()?;
    if existing
        .as_ref()
        .is_some_and(|g| g.operations != [ResourceOperation::Use])
    {
        return Err(Failure::new(
            TaskErrorCode::AuthDenied,
            "operator command cannot replace or revoke Manage or noncanonical Use operations",
            false,
        ));
    }
    let after = match command.operation {
        Operation::Add => Some(Grant::new(
            reference,
            principal.clone(),
            vec![ResourceOperation::Use],
            command.not_after,
        )),
        Operation::Revoke => existing.clone().map(|mut grant| {
            grant.revoked = true;
            grant
        }),
        Operation::List => return Err(io::corrupt("unexpected list mutation")),
    };
    let changed = existing != after;
    if changed {
        let grant = after
            .as_ref()
            .ok_or_else(|| io::corrupt("mutation cannot remove a grant"))?;
        let bytes = canonical(&crate::n2_store::encode_grant(grant))?;
        if bytes.len() as u64 > io::RECORD_LIMIT {
            return Err(io::capacity("grant exceeds 16 KiB", false));
        }
        let mutation = audit::Mutation {
            id: crate::n3_acceptance::new_task_id()
                .map_err(|error| Failure {
                    error,
                    phase: "preflight",
                    may_have_applied: false,
                })?
                .as_str()
                .to_owned(),
            operation: command.operation.name(),
            scope: scope.value(),
            resource: grant.resource.name.as_str().to_owned(),
            principal: principal.0.clone(),
            actor: actor.0,
            before: before
                .as_ref()
                .map(|r| sha256(&r.bytes).as_str().to_owned()),
            after: sha256(&bytes).as_str().to_owned(),
        };
        let (intent, applied) = journal.records(&mutation)?;
        check()?;
        io::check_grant_before(&path, before.as_ref())?;
        journal
            .append(&roots, &lease, &intent)
            .map_err(|error| error.at("audit_intent", false))?;
        check().map_err(|error| error.at("grant_write", false))?;
        io::atomic_grant(&roots, &lease, &path, before.as_ref(), &bytes, || {
            #[cfg(test)]
            run_authority_test_hook("publish");
            check()?;
            journal.check(&roots)
        })
        .map_err(|error| {
            if error.may_have_applied {
                error
            } else {
                error.at("grant_write", false)
            }
        })?;
        check().map_err(|error| error.at("audit_applied", true))?;
        journal
            .append(&roots, &lease, &applied)
            .map_err(|error| error.at("audit_applied", true))?;
    } else {
        #[cfg(test)]
        run_authority_test_hook("noop");
        check()?;
        journal.check(&roots)?;
        io::check_grant_before(&path, before.as_ref())?;
    }
    Ok(
        json!({"schema_version":1,"verdict":"PASS","command":format!("task-provider grant {}",command.operation.name()),
        "scope":scope.value(),"operation":command.operation.name(),"changed":changed,"grant":after.as_ref().map(grant_value)}),
    )
}

#[cfg(test)]
type AuthorityTestHook = (&'static str, Box<dyn FnOnce()>);
#[cfg(test)]
std::thread_local! {
    static AUTHORITY_TEST_HOOK: std::cell::RefCell<Option<AuthorityTestHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_authority_test_hook(stage: &str) {
    let hook = AUTHORITY_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _)| *expected == stage)
        {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook();
    }
}
