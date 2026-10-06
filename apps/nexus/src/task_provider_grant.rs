//! Explicit local operator access to the existing scoped N2 Use grant table.
//! No daemon RPC, identity provisioning, name resolution or Task ownership.
use std::path::{Component, PathBuf};

use nexus_domain::task::{MAX_INTEGER, TaskError, TaskErrorCode};
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
#[path = "task_provider_grant/linux.rs"]
mod linux;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    Add,
    Revoke,
    List,
}
impl Operation {
    fn name(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Revoke => "revoke",
            Self::List => "list",
        }
    }
}
#[derive(Debug, Clone)]
struct Command {
    operation: Operation,
    config: PathBuf,
    resource: Option<String>,
    principal: Option<String>,
    self_target: bool,
    not_after: Option<u64>,
}

fn principal_valid(value: &str) -> bool {
    value.strip_prefix("ed25519:").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn parse(args: &[String]) -> std::result::Result<Command, String> {
    let [family, operation, rest @ ..] = args else {
        return Err("expected task-provider grant <add|revoke|list>".into());
    };
    if family != "grant" {
        return Err("expected grant subcommand".into());
    }
    let operation = match operation.as_str() {
        "add" => Operation::Add,
        "revoke" => Operation::Revoke,
        "list" => Operation::List,
        _ => return Err("unknown grant operation".into()),
    };
    let mut config = None;
    let mut resource = None;
    let mut principal = None;
    let mut self_target = false;
    let mut not_after = None;
    let mut index = 0;
    while index < rest.len() {
        let flag = rest[index].as_str();
        if flag == "--self" {
            if self_target || principal.is_some() || operation == Operation::List {
                return Err("duplicate, conflicting or inapplicable --self".into());
            }
            self_target = true;
            index += 1;
            continue;
        }
        let value = rest
            .get(index + 1)
            .filter(|s| !s.is_empty() && !s.starts_with('-'))
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--config" if config.is_none() => config = Some(PathBuf::from(value)),
            "--resource" if resource.is_none() => {
                nexus_domain::ResourceName::new(value).map_err(|_| "invalid resource name")?;
                resource = Some(value.clone());
            }
            "--principal"
                if principal.is_none() && !self_target && operation != Operation::List =>
            {
                if !principal_valid(value) {
                    return Err(
                        "principal requires ed25519: and 32 lowercase hexadecimal digits".into(),
                    );
                }
                principal = Some(value.clone());
            }
            "--not-after" if not_after.is_none() && operation == Operation::Add => {
                if !value.bytes().all(|c| c.is_ascii_digit()) {
                    return Err("not-after requires a nonnegative decimal integer".into());
                }
                not_after = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|v| *v <= MAX_INTEGER)
                        .ok_or("not-after exceeds the exact integer range")?,
                );
            }
            _ => return Err(format!("unknown, duplicate or inapplicable option {flag}")),
        }
        index += 2;
    }
    let config = config.ok_or("--config is required")?;
    if !config.is_absolute() || config.components().any(|c| c == Component::ParentDir) {
        return Err("config requires an absolute existing path without ..".into());
    }
    if operation != Operation::List && (resource.is_none() || (!self_target && principal.is_none()))
    {
        return Err("mutation requires --resource and exactly one of --self or --principal".into());
    }
    Ok(Command {
        operation,
        config,
        resource,
        principal,
        self_target,
        not_after,
    })
}

#[derive(Debug)]
struct Failure {
    error: TaskError,
    phase: &'static str,
    may_have_applied: bool,
}
impl Failure {
    fn new(code: TaskErrorCode, reason: impl Into<String>, retryable: bool) -> Self {
        Self {
            error: TaskError::new(code, reason, retryable),
            phase: "preflight",
            may_have_applied: false,
        }
    }
    fn at(mut self, phase: &'static str, may_have_applied: bool) -> Self {
        self.phase = phase;
        self.may_have_applied = may_have_applied;
        self
    }
    fn render(&self) -> Value {
        json!({"schema_version":1,"verdict":"FAIL","error":{"code":self.error.code.as_str(),"reason":self.error.reason,"retryable":self.error.retryable},"phase":self.phase,"mutation_may_have_applied":self.may_have_applied})
    }
}
type Result<T> = std::result::Result<T, Failure>;

/// `args` starts with `grant`; all business results are structured and exit 0.
pub fn run(args: &[String], _json_mode: bool) -> i32 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(reason) => {
            eprintln!("error: {reason}");
            return 2;
        }
    };
    #[cfg(target_os = "linux")]
    let result = linux::execute(&command);
    #[cfg(not(target_os = "linux"))]
    let result: Result<Value> = {
        let _ = command;
        Err(Failure::new(
            TaskErrorCode::UnsupportedCapability,
            "local operator grants require Linux",
            false,
        ))
    };
    println!("{}", result.unwrap_or_else(|error| error.render()));
    0
}
