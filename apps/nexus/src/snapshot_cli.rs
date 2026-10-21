//! Explicit immutable-input CLI. Parsing is pure; Linux adapters own local IO.
use crate::localapi_client::LocalApiTarget;
#[cfg(target_os = "linux")]
use nexus_control_api::snapshot::SnapshotRequest;
use nexus_control_api::snapshot::{CanonicalDto, SnapshotEnvelope, TaskError, UploadId, Value};
use nexus_domain::task::{TaskId, relative_path};
use nexus_workspace::snapshot::SnapshotSelection;
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

#[cfg(target_os = "linux")]
mod linux;

enum Command {
    Freeze {
        workspace: String,
        config: PathBuf,
        commit: String,
        selection: SnapshotSelection,
        output: PathBuf,
    },
    Upload {
        bundle: PathBuf,
        provider: String,
        resource: String,
        key: String,
    },
    Query {
        upload_id: UploadId,
        cancel: bool,
    },
}
struct Parsed {
    command: Command,
    json: bool,
    target: Option<LocalApiTarget>,
}

/// Recognize the raw command before the legacy default-target resolver does IO.
pub fn handles(args: &[String]) -> bool {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--json" => index += 1,
            "--addr" | "--socket" => {
                // A missing target value can otherwise consume the command
                // name and fall through to the legacy resolver's runtime IO.
                if args.get(index + 1).is_some_and(|value| value == "snapshot")
                    && args.get(index + 2).is_some_and(|verb| {
                        matches!(verb.as_str(), "freeze" | "upload" | "status" | "cancel")
                    })
                {
                    return true;
                }
                index += if args
                    .get(index + 1)
                    .is_some_and(|value| !value.starts_with('-'))
                {
                    2
                } else {
                    1
                };
            }
            "snapshot" => return true,
            flag if flag.starts_with('-') => {
                // Unknown global prefixes must reach the pure snapshot parser,
                // even if their would-be value precedes the command. An actual
                // legacy command is never scanned for an identifier named snapshot.
                return args[index + 1..].iter().any(|arg| arg == "snapshot");
            }
            _ => return false,
        }
    }
    false
}

fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.contains('\0')
        || path.components().any(|c| c == Component::ParentDir)
    {
        return Err("snapshot host paths must be absolute without '..' or NUL".into());
    }
    Ok(path.to_owned())
}
fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut positional = Vec::new();
    let mut options: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut json = false;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--json" {
            if json {
                return Err("duplicate --json".into());
            }
            json = true;
            index += 1;
        } else if arg.starts_with('-') {
            if !matches!(
                arg.as_str(),
                "--config"
                    | "--commit"
                    | "--include"
                    | "--exclude"
                    | "--executable"
                    | "--output"
                    | "--bundle"
                    | "--provider"
                    | "--resource"
                    | "--key"
                    | "--addr"
                    | "--socket"
            ) {
                return Err("unknown snapshot option".into());
            }
            let value = args
                .get(index + 1)
                .filter(|s| !s.is_empty() && !s.starts_with("--"))
                .ok_or_else(|| format!("missing value for {arg}"))?;
            let values = options.entry(arg.as_str()).or_default();
            if !matches!(arg.as_str(), "--include" | "--exclude" | "--executable")
                && !values.is_empty()
                || values.contains(&value.as_str())
            {
                return Err(format!("duplicate {arg}"));
            }
            values.push(value);
            index += 2;
        } else {
            positional.push(arg.as_str());
            index += 1;
        }
    }
    let target = match (options.remove("--addr"), options.remove("--socket")) {
        (Some(_), Some(_)) => return Err("--addr and --socket are mutually exclusive".into()),
        (Some(values), None) => {
            let address: std::net::SocketAddr = values[0]
                .parse()
                .map_err(|_| "snapshot target must be numeric loopback")?;
            if !address.ip().is_loopback() {
                return Err("snapshot target must be loopback".into());
            }
            Some(LocalApiTarget::Tcp(values[0].into()))
        }
        (None, Some(values)) => Some(LocalApiTarget::Socket(absolute(values[0])?)),
        (None, None) => None,
    };
    fn take(options: &mut BTreeMap<&str, Vec<&str>>, key: &str) -> Result<String, String> {
        options
            .remove(key)
            .map(|v| v[0].to_owned())
            .ok_or_else(|| format!("snapshot requires {key}"))
    }
    fn rules(options: &mut BTreeMap<&str, Vec<&str>>, key: &str) -> Result<Vec<String>, String> {
        options
            .remove(key)
            .unwrap_or_default()
            .into_iter()
            .map(|rule| {
                if rule != "." {
                    relative_path(rule).map_err(|e| e.to_string())?;
                }
                Ok(rule.to_owned())
            })
            .collect()
    }
    let command = match positional.as_slice() {
        ["snapshot", "freeze", workspace] => {
            if target.is_some() {
                return Err("freeze is offline and accepts no target".into());
            }
            if workspace.is_empty()
                || !workspace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err("invalid local Workspace ID".into());
            }
            TaskId::new((*workspace).to_owned()).map_err(|e| e.to_string())?;
            let config = absolute(&take(&mut options, "--config")?)?;
            let output = absolute(&take(&mut options, "--output")?)?;
            if output.file_name().is_none() {
                return Err("output must name a new directory".into());
            }
            let commit = take(&mut options, "--commit")?;
            if commit.len() != 16
                || !commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("commit must be a legacy lowercase content ID".into());
            }
            let selection = SnapshotSelection {
                include: rules(&mut options, "--include")?,
                exclude: rules(&mut options, "--exclude")?,
                executable: rules(&mut options, "--executable")?,
            };
            selection
                .digest(crate::n3_acceptance::sha256)
                .map_err(|e| e.to_string())?;
            Command::Freeze {
                workspace: (*workspace).into(),
                config,
                commit,
                selection,
                output,
            }
        }
        ["snapshot", "upload"] => {
            let bundle = absolute(&take(&mut options, "--bundle")?)?;
            let provider = take(&mut options, "--provider")?;
            let resource = take(&mut options, "--resource")?;
            let key = take(&mut options, "--key")?;
            for id in [&provider, &resource, &key] {
                TaskId::new(id.clone()).map_err(|e| e.to_string())?;
            }
            Command::Upload {
                bundle,
                provider,
                resource,
                key,
            }
        }
        ["snapshot", verb @ ("status" | "cancel"), id] => Command::Query {
            upload_id: UploadId::new((*id).into()).map_err(|e| e.to_string())?,
            cancel: *verb == "cancel",
        },
        _ => return Err("invalid snapshot command or missing required argument".into()),
    };
    if !options.is_empty() {
        return Err("option is not valid for this snapshot operation".into());
    }
    Ok(Parsed {
        command,
        json,
        target,
    })
}

fn failure(error: TaskError, upload_id: Option<UploadId>) -> SnapshotEnvelope {
    SnapshotEnvelope::Error { error, upload_id }
}
#[cfg(target_os = "linux")]
fn request(target: &LocalApiTarget, request: &SnapshotRequest) -> SnapshotEnvelope {
    crate::task_localapi::execute_snapshot(target, request).unwrap_or_else(|error| {
        let id = match request {
            SnapshotRequest::Begin { .. } => None,
            SnapshotRequest::Get { upload_id }
            | SnapshotRequest::Cancel { upload_id }
            | SnapshotRequest::Seal { upload_id }
            | SnapshotRequest::PutChunk { upload_id, .. } => Some(upload_id.clone()),
        };
        failure(error, id)
    })
}
fn render(envelope: SnapshotEnvelope, json: bool) -> String {
    if json {
        return String::from_utf8(envelope.to_value().canonical_bytes()).expect("canonical UTF-8");
    }
    match envelope {
        SnapshotEnvelope::Upload(view) => format!(
            "PASS upload_id={} state={} reserved_bytes={} snapshot={}",
            view.upload_id.as_str(),
            match view.state {
                nexus_control_api::snapshot::UploadState::Receiving => "Receiving",
                nexus_control_api::snapshot::UploadState::Staged => "Staged",
                nexus_control_api::snapshot::UploadState::Cancelling => "Cancelling",
                nexus_control_api::snapshot::UploadState::Cancelled => "Cancelled",
            },
            view.reserved_bytes,
            view.snapshot.snapshot_id.as_str()
        ),
        SnapshotEnvelope::Error { error, .. } => {
            format!("FAIL {}: {}", error.code.as_str(), error.reason)
        }
    }
}
fn local_value(result: Result<(nexus_domain::task::SnapshotRef, PathBuf), TaskError>) -> Value {
    let mut fields = BTreeMap::from([
        ("schema_version".into(), 1u64.to_value()),
        ("command".into(), "snapshot freeze".to_owned().to_value()),
    ]);
    match result {
        Ok((snapshot, bundle)) => {
            fields.insert("verdict".into(), "PASS".to_owned().to_value());
            fields.insert("snapshot".into(), snapshot.to_value());
            fields.insert(
                "bundle_path".into(),
                bundle.to_string_lossy().into_owned().to_value(),
            );
        }
        Err(error) => {
            fields.insert("verdict".into(), "FAIL".to_owned().to_value());
            fields.insert("error".into(), error.to_value());
        }
    }
    Value::Object(fields)
}

/// Usage errors return Err (exit2); all handled business outcomes render exit0.
pub fn run(args: &[String]) -> Result<String, String> {
    let parsed = parse(args)?;
    #[cfg(target_os = "linux")]
    let result = match parsed.command {
        Command::Freeze {
            workspace,
            config,
            commit,
            selection,
            output,
        } => {
            let result = linux::freeze(&workspace, &config, &commit, &selection, &output);
            return render_local(result, parsed.json);
        }
        Command::Upload {
            bundle,
            provider,
            resource,
            key,
        } => {
            // Bundle validation precedes default-target, credential and network IO.
            match linux::Bundle::open(&bundle) {
                Ok(mut bundle) => linux::upload(
                    &mut bundle,
                    parsed
                        .target
                        .unwrap_or_else(crate::localapi_client::default_target),
                    provider,
                    resource,
                    key,
                ),
                Err(error) => failure(error, None),
            }
        }
        Command::Query { upload_id, cancel } => {
            let target = parsed
                .target
                .unwrap_or_else(crate::localapi_client::default_target);
            request(
                &target,
                &if cancel {
                    SnapshotRequest::Cancel { upload_id }
                } else {
                    SnapshotRequest::Get { upload_id }
                },
            )
        }
    };
    #[cfg(not(target_os = "linux"))]
    let result = {
        let error = TaskError::new(
            nexus_control_api::snapshot::TaskErrorCode::UnsupportedCapability,
            "snapshot adapter requires Linux",
            false,
        );
        let _target = parsed.target;
        match parsed.command {
            Command::Freeze {
                workspace,
                config,
                commit,
                selection,
                output,
            } => {
                let _ = (workspace, config, commit, selection, output);
                return render_local(Err(error), parsed.json);
            }
            Command::Upload {
                bundle,
                provider,
                resource,
                key,
            } => {
                let _ = (bundle, provider, resource, key);
                failure(error, None)
            }
            Command::Query { upload_id, cancel } => {
                let _ = cancel;
                failure(error, Some(upload_id))
            }
        }
    };
    Ok(render(result, parsed.json))
}
fn render_local(
    result: Result<(nexus_domain::task::SnapshotRef, PathBuf), TaskError>,
    json: bool,
) -> Result<String, String> {
    if json {
        return String::from_utf8(local_value(result).canonical_bytes()).map_err(|e| e.to_string());
    }
    Ok(match result {
        Ok((snapshot, bundle)) => format!(
            "PASS snapshot={} bundle_path={}",
            snapshot.snapshot_id.as_str(),
            bundle.display()
        ),
        Err(error) => format!("FAIL {}: {}", error.code.as_str(), error.reason),
    })
}

#[cfg(test)]
mod raw_dispatch_tests {
    use super::{handles, parse};
    #[test]
    fn malformed_snapshot_prefixes_reach_pure_parser_and_legacy_ids_do_not() {
        for raw in [
            "--bogus snapshot status probe --json",
            "--bogus value snapshot status probe",
            "--addr snapshot status probe",
            "--socket snapshot cancel probe",
            "--addr --json snapshot status probe",
            "--bogus=value snapshot status probe",
            "--json --bogus snapshot status probe",
        ] {
            let args: Vec<String> = raw.split_whitespace().map(str::to_owned).collect();
            assert!(handles(&args), "{raw}");
            assert!(parse(&args).is_err(), "{raw}");
        }
        for raw in [
            "task show snapshot",
            "--json task show snapshot",
            "--socket snapshot task show id",
            "--addr 127.0.0.1:9 task show snapshot",
        ] {
            let args: Vec<String> = raw.split_whitespace().map(str::to_owned).collect();
            assert!(!handles(&args), "{raw}");
        }
    }
}
