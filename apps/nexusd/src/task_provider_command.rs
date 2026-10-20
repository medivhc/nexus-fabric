//! Pure argument validation precedes every platform and persistence operation.
use nexus_domain::task::TaskId;
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: nexusd task-provider init --config <absolute-root> --provider <id> --workspace <id> --capacity <absolute-policy-json> [--json]\n       nexusd task-provider check --config <absolute-root> [--json]";

enum Command {
    Init {
        config: PathBuf,
        provider: String,
        workspace: String,
        capacity: PathBuf,
    },
    Check {
        config: PathBuf,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "task-provider init",
            Self::Check { .. } => "task-provider check",
        }
    }
}

fn absolute_path(value: String) -> Result<PathBuf, String> {
    let path = Path::new(&value);
    if value.contains('\0')
        || !path.is_absolute()
        || path.components().any(|part| part == Component::ParentDir)
    {
        return Err("paths must be absolute and must not contain .. or NUL".into());
    }
    Ok(path.to_owned())
}

fn parse(args: &[String]) -> Result<Command, String> {
    let action = args.first().map(String::as_str);
    if !matches!(action, Some("init" | "check")) {
        return Err("expected init or check".into());
    }
    let init = action == Some("init");
    let (mut config, mut provider, mut workspace, mut capacity) = (None, None, None, None);
    let mut json_seen = false;
    let mut at = 1;
    while at < args.len() {
        let token = &args[at];
        if token == "--json" {
            if json_seen {
                return Err("duplicate --json".into());
            }
            json_seen = true;
            at += 1;
            continue;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (token.as_str(), None),
        };
        let slot = match flag {
            "--config" => &mut config,
            "--provider" if init => &mut provider,
            "--workspace" if init => &mut workspace,
            "--capacity" if init => &mut capacity,
            _ => return Err(format!("unknown or inapplicable option: {flag}")),
        };
        if slot.is_some() {
            return Err(format!("duplicate option: {flag}"));
        }
        let value = match inline {
            Some(value) => value,
            None => {
                at += 1;
                args.get(at)
                    .filter(|value| !value.starts_with("--"))
                    .map(String::as_str)
                    .ok_or_else(|| format!("missing value: {flag}"))?
            }
        };
        if value.is_empty() {
            return Err(format!("missing value: {flag}"));
        }
        *slot = Some(value.to_owned());
        at += 1;
    }
    let config = absolute_path(config.ok_or("missing --config")?)?;
    if !init {
        return Ok(Command::Check { config });
    }
    let provider = provider.ok_or("missing --provider")?;
    let workspace = workspace.ok_or("missing --workspace")?;
    TaskId::new(provider.clone()).map_err(|_| "invalid provider identifier")?;
    TaskId::new(workspace.clone()).map_err(|_| "invalid workspace identifier")?;
    let capacity = absolute_path(capacity.ok_or("missing --capacity")?)?;
    Ok(Command::Init {
        config,
        provider,
        workspace,
        capacity,
    })
}

pub(super) fn run(args: &[String]) -> ExitCode {
    let command = match parse(args) {
        Ok(command) => command,
        Err(reason) => {
            eprintln!("{reason}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    println!("{}", execute(&command));
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
fn execute(command: &Command) -> Value {
    let result = match command {
        Command::Init {
            config,
            provider,
            workspace,
            capacity,
        } => nexusd::task_provider_init::init(config, provider, workspace, capacity),
        Command::Check { config } => nexusd::task_provider_init::check(config),
    };
    match result {
        Ok(status) => {
            let mut value = json!({
                "schema_version":1, "verdict":"PASS", "command":command.name(),
                "scope":{"provider":status.provider, "workspace":status.workspace},
                "principal":status.principal,
            });
            match command {
                Command::Init { .. } => value["changed"] = json!(status.changed),
                Command::Check { .. } => {
                    value["initialized"] = json!(true);
                    value["policy_digest"] = json!(status.policy_digest);
                }
            }
            value
        }
        Err(failure) => json!({
            "schema_version":1, "verdict":"FAIL", "command":command.name(),
            "error":{"code":failure.error.code.as_str(), "reason":failure.error.reason,
                "retryable":failure.error.retryable},
            "phase":failure.phase,
            "mutation_may_have_applied":failure.mutation_may_have_applied,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute(command: &Command) -> Value {
    // The unsupported branch deliberately does not inspect any supplied path.
    match command {
        Command::Init {
            config,
            provider,
            workspace,
            capacity,
        } => {
            let _ = (config, provider, workspace, capacity);
        }
        Command::Check { config } => {
            let _ = config;
        }
    }
    json!({
        "schema_version":1, "verdict":"FAIL", "command":command.name(),
        "error":{"code":"UNSUPPORTED_CAPABILITY", "reason":"task-provider init/check requires Linux",
            "retryable":false},
        "phase":"platform", "mutation_may_have_applied":false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn scope_identifiers_keep_existing_task_id_grammar() {
        let parsed = parse(&args(&[
            "init",
            "--config",
            "/config",
            "--provider=--provider/with/slash",
            "--workspace",
            "scope/with space",
            "--capacity",
            "/policy.json",
        ]))
        .unwrap();
        match parsed {
            Command::Init {
                provider,
                workspace,
                ..
            } => {
                assert_eq!(provider, "--provider/with/slash");
                assert_eq!(workspace, "scope/with space");
            }
            _ => panic!("expected init"),
        }
    }

    #[test]
    fn malformed_arguments_are_rejected_without_path_lookup() {
        let invalid = [
            vec!["check"],
            vec!["check", "--config", "relative"],
            vec!["check", "--config", "/config/../other"],
            vec!["check", "--config", "/missing", "--config=/other"],
            vec!["check", "--config", "--json"],
            vec!["check", "--config", "/missing", "--json", "--json"],
            vec!["check", "--config", "/missing", "--provider", "provider"],
            vec!["check", "--config", "/missing", "--addr=127.0.0.1:1"],
            vec!["check", "--config", "/missing", "--socket", "/socket"],
            vec!["check", "--config", "/missing", "--json=true"],
        ];
        for row in invalid {
            assert!(parse(&args(&row)).is_err(), "{row:?}");
        }
    }
}
