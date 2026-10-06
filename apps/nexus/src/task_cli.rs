//! Thin N3 front-end: parse → strict versioned request → Application API DTO.
//! No TaskOwner, implicit shell, executor or uncontracted HTTP route.
use nexus_control_api::task::{
    ArtifactId, CanonicalDto, LogStream, MAX_INTEGER, MAX_PAGE_BYTES, SubmitTaskRequest,
    TaskEnvelope, TaskError, TaskErrorCode, TaskId, TaskRequest,
};
use std::io::Read;
use std::path::PathBuf;

const MAX_REQUEST_BYTES: u64 = 1_048_576;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCliCommand {
    Submit {
        request_file: PathBuf,
    },
    Request(TaskRequest),
    /// Always no-replace: the receiver verifies SHA-256 and publishes
    /// atomically without overwriting. There is no overwrite option.
    Download {
        artifact_id: ArtifactId,
        output: PathBuf,
    },
}
fn identifier(value: &str) -> Result<TaskId, String> {
    if value.starts_with('-') {
        return Err("task ID cannot be an option".into());
    }
    TaskId::new(value.to_string()).map_err(|e| e.to_string())
}
fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("offset must be a nonnegative decimal integer".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|v| *v <= MAX_INTEGER)
        .ok_or_else(|| "offset must be <= 2^53-1".into())
}
fn option_value(value: &str) -> Result<&str, String> {
    if value.is_empty() || value.starts_with('-') {
        Err("missing option value".into())
    } else {
        Ok(value)
    }
}
/// Global --json / daemon target flags are handled by the shared CLI dispatcher.
/// This parser rejects unknown, duplicate and incomplete operation arguments.
pub fn parse(args: &[String]) -> Result<TaskCliCommand, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["task", "submit", "--request", path] => Ok(TaskCliCommand::Submit {
            request_file: PathBuf::from(option_value(path)?),
        }),
        ["task", op @ ("show" | "cancel" | "artifacts"), id] => {
            let task_id = identifier(id)?;
            Ok(TaskCliCommand::Request(match *op {
                "show" => TaskRequest::Get { task_id },
                "cancel" => TaskRequest::Cancel { task_id },
                _ => TaskRequest::ListArtifacts { task_id },
            }))
        }
        ["task", "logs", id, rest @ ..] => {
            let task_id = identifier(id)?;
            let mut stream = None;
            let mut offset = None;
            for chunk in rest.chunks(2) {
                let [flag, value] = chunk else {
                    return Err("missing logs option value".into());
                };
                match *flag {
                    "--stream" if stream.is_none() => {
                        stream = Some(match *value {
                            "stdout" => LogStream::Stdout,
                            "stderr" => LogStream::Stderr,
                            _ => return Err("stream must be stdout or stderr".into()),
                        })
                    }
                    "--offset" if offset.is_none() => offset = Some(decimal(value)?),
                    _ => return Err("unknown or duplicate logs option".into()),
                }
            }
            Ok(TaskCliCommand::Request(TaskRequest::ReadLogs {
                task_id,
                stream: stream.ok_or_else(|| "logs requires --stream".to_string())?,
                offset: offset.ok_or_else(|| "logs requires --offset".to_string())?,
                max_bytes: MAX_PAGE_BYTES,
            }))
        }
        ["artifact", "get", id, "--output", path] => {
            if id.starts_with('-') {
                return Err("artifact ID cannot be an option".into());
            }
            Ok(TaskCliCommand::Download {
                artifact_id: ArtifactId::new(id.to_string()).map_err(|e| e.to_string())?,
                output: PathBuf::from(option_value(path)?),
            })
        }
        _ => Err("invalid task/artifact command syntax".into()),
    }
}
impl TaskCliCommand {
    /// Request files are read boundedly and decoded with the established
    /// duplicate-key / no-float / strict domain validator. Output paths stay local.
    pub fn prepare(&self) -> Result<TaskRequest, TaskError> {
        match self {
            Self::Request(request) => {
                request.validate()?;
                Ok(request.clone())
            }
            Self::Download { artifact_id, .. } => Ok(TaskRequest::GetArtifact {
                artifact_id: artifact_id.clone(),
                offset: 0,
                max_bytes: MAX_PAGE_BYTES,
            }),
            Self::Submit { request_file } => {
                let file = open_request_file(request_file)?;
                let mut bytes = Vec::new();
                file.take(MAX_REQUEST_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| TaskError::invalid(format!("cannot read request file: {e}")))?;
                if bytes.len() as u64 > MAX_REQUEST_BYTES {
                    return Err(TaskError::new(
                        TaskErrorCode::CapacityUnavailable,
                        "CLI request file exceeds adapter capacity of 1 MiB",
                        false,
                    ));
                }
                let request = crate::n3_acceptance::decode_dto::<SubmitTaskRequest>(&bytes)?;
                Ok(TaskRequest::Submit {
                    request: Box::new(request),
                })
            }
        }
    }
}
/// Execute through the authenticated local daemon and verified local receiver.
pub fn run(
    args: &[String],
    json: bool,
    target: &crate::localapi_client::LocalApiTarget,
) -> Result<String, String> {
    let command = parse(args)?;
    let output = if let TaskCliCommand::Download {
        artifact_id,
        output,
    } = &command
    {
        download(target, artifact_id, output).unwrap_or_else(|error| TaskEnvelope::Error {
            error,
            task_id: None,
        })
    } else {
        match command.prepare() {
            Ok(request) => {
                crate::task_localapi::execute(target, &request).unwrap_or_else(|error| {
                    TaskEnvelope::Error {
                        error,
                        task_id: request.task_id().cloned(),
                    }
                })
            }
            Err(error) => TaskEnvelope::Error {
                error,
                task_id: None,
            },
        }
    };
    render(output, json)
}

#[cfg(target_os = "linux")]
fn download(
    target: &crate::localapi_client::LocalApiTarget,
    artifact_id: &ArtifactId,
    output: &std::path::Path,
) -> Result<TaskEnvelope, TaskError> {
    use nexus_control_api::task::TaskResponse;
    let request = |offset| TaskRequest::GetArtifact {
        artifact_id: artifact_id.clone(),
        offset,
        max_bytes: MAX_PAGE_BYTES,
    };
    // Probe before any output IO, including inspection of an existing receiver.
    let probe = crate::task_localapi::execute(target, &request(0))?;
    let mut page = match probe {
        TaskEnvelope::Success(TaskResponse::Artifact(page)) => page,
        error @ TaskEnvelope::Error { .. } => return Ok(error),
        _ => {
            return Err(TaskError::invalid(
                "Artifact probe returned a different operation",
            ));
        }
    };
    let record = page.record.clone();
    let mut receiver = crate::artifact_download::ArtifactDownload::open(&record, output)?;
    let mut offset = receiver.offset();
    while offset < record.size_bytes {
        // Resume requests never rewrite the prefix returned by the mandatory probe.
        if page.offset != offset {
            page = match crate::task_localapi::execute(target, &request(offset))? {
                TaskEnvelope::Success(TaskResponse::Artifact(page)) => page,
                error @ TaskEnvelope::Error { .. } => return Ok(error),
                _ => {
                    return Err(TaskError::invalid(
                        "Artifact page returned a different operation",
                    ));
                }
            };
        }
        if page.record != record || page.bytes.is_empty() || page.next_offset <= offset {
            return Err(TaskError::invalid(
                "Artifact record changed or page made no progress",
            ));
        }
        offset = receiver.append(offset, &page.bytes)?;
        if offset != page.next_offset {
            return Err(TaskError::invalid(
                "Artifact page differs from durable receiver offset",
            ));
        }
    }
    // This fresh remote authorization also applies to empty/complete/published replay.
    let final_page = crate::task_localapi::execute(target, &request(record.size_bytes))?;
    match &final_page {
        TaskEnvelope::Success(TaskResponse::Artifact(page))
            if page.record == record
                && page.offset == record.size_bytes
                && page.next_offset == record.size_bytes
                && page.bytes.is_empty()
                && page.eof => {}
        error @ TaskEnvelope::Error { .. } => return Ok(error.clone()),
        _ => {
            return Err(TaskError::invalid(
                "Artifact final authorization requires the same record and empty EOF",
            ));
        }
    }
    receiver.finish()?;
    Ok(final_page)
}

#[cfg(not(target_os = "linux"))]
fn download(
    _target: &crate::localapi_client::LocalApiTarget,
    _artifact_id: &ArtifactId,
    _output: &std::path::Path,
) -> Result<TaskEnvelope, TaskError> {
    Err(TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "verified Artifact download requires Linux",
        false,
    ))
}
fn render(output: TaskEnvelope, json: bool) -> Result<String, String> {
    if json {
        String::from_utf8(output.to_value().canonical_bytes()).map_err(|e| e.to_string())
    } else {
        match output {
            TaskEnvelope::Error { error, task_id } => Ok(format!(
                "FAIL {}{}: {}",
                error.code.as_str(),
                task_id.map_or_else(String::new, |id| format!(" task_id={}", id.as_str())),
                error.reason
            )),
            TaskEnvelope::Success(nexus_control_api::task::TaskResponse::Task(view)) => {
                Ok(format!(
                    "PASS task_id={} phase={} outcome={} cancellation={} cancel_request={} observation={}",
                    view.task_id.as_str(),
                    view.phase.as_str(),
                    view.outcome.as_str(),
                    view.cancellation.state.as_str(),
                    view.cancel_request.state.as_str(),
                    view.observation.as_str()
                ))
            }
            TaskEnvelope::Success(response) => {
                String::from_utf8(TaskEnvelope::Success(response).to_value().canonical_bytes())
                    .map_err(|e| e.to_string())
            }
        }
    }
}
// Check before opening so a known FIFO/device is never opened. The fd check
// remains authoritative because the path may change after this check.
pub(crate) fn open_request_file(path: &std::path::Path) -> Result<std::fs::File, TaskError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| TaskError::invalid(format!("cannot inspect request file: {e}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TaskError::invalid(
            "request input must be a regular file, not a link or device",
        ));
    }
    open_checked_request_file(path)
}
// Nonblocking open closes the check/open FIFO replacement window. On Windows,
// opening a reparse point itself prevents following a replaced link to a pipe.
fn open_checked_request_file(path: &std::path::Path) -> Result<std::fs::File, TaskError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    configure_safe_request_open(&mut options)?;
    let file = options
        .open(path)
        .map_err(|e| TaskError::invalid(format!("cannot read request file: {e}")))?;
    let metadata = file
        .metadata()
        .map_err(|e| TaskError::invalid(format!("cannot inspect opened request file: {e}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TaskError::invalid(
            "opened request input must be a regular file",
        ));
    }
    Ok(file)
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
fn configure_safe_request_open(options: &mut std::fs::OpenOptions) -> Result<(), TaskError> {
    use std::os::unix::fs::OpenOptionsExt;
    // These Linux ABIs use O_NONBLOCK=0x0800 and O_NOFOLLOW=0x20000.
    // Do not reuse these on MIPS/Alpha or unknown ABIs.
    options.custom_flags(nexus_platform_linux::tun::O_NONBLOCK | 0x0002_0000);
    Ok(())
}
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn configure_safe_request_open(options: &mut std::fs::OpenOptions) -> Result<(), TaskError> {
    use std::os::unix::fs::OpenOptionsExt;
    // BSD/Darwin open(2): O_NONBLOCK=0x0004, O_NOFOLLOW=0x0100.
    options.custom_flags(0x0004 | 0x0100);
    Ok(())
}
#[cfg(windows)]
fn configure_safe_request_open(options: &mut std::fs::OpenOptions) -> Result<(), TaskError> {
    use std::os::windows::fs::OpenOptionsExt;
    // Win32 CreateFileW FILE_FLAG_OPEN_REPARSE_POINT: do not follow links.
    // This is a local regular-file reader, not a named-pipe/network-share reader.
    options.custom_flags(0x0020_0000);
    Ok(())
}
#[cfg(not(any(
    all(
        target_os = "linux",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ),
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    windows
)))]
fn configure_safe_request_open(_options: &mut std::fs::OpenOptions) -> Result<(), TaskError> {
    Err(TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "safe nonblocking request file open is not supported on this platform ABI",
        false,
    ))
}

/// Capability probe only: no daemon adapter has been installed. This returns no
/// accepted Task, sends no credentials or request bytes, and never creates output.
pub fn run_unavailable(args: &[String], json: bool) -> Result<String, String> {
    let command = parse(args)?;
    let (error, task_id) = match command.prepare() {
        Ok(request) => (
            TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "N3 authenticated daemon TaskApplicationService adapter is not installed",
                false,
            ),
            request.task_id().cloned(),
        ),
        Err(error) => (error, None),
    };
    let output = TaskEnvelope::Error { error, task_id };
    if json {
        String::from_utf8(output.to_value().canonical_bytes()).map_err(|e| e.to_string())
    } else if let TaskEnvelope::Error { error, task_id } = output {
        Ok(format!(
            "FAIL {}{}: {}",
            error.code.as_str(),
            task_id.map_or_else(String::new, |id| format!(" task_id={}", id.as_str())),
            error.reason
        ))
    } else {
        unreachable!()
    }
}

#[cfg(test)]
mod tests;
