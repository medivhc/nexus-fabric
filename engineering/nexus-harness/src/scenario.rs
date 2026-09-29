//! Scenario contracts: parse scenarios/**/*.toml and execute the ones that
//! declare a [when].command, evaluating [[expect]] entries against the JSON
//! output. Scenarios without a command are static contracts (recorded UNKNOWN).

use crate::config::Config;
use crate::gates::Gate;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone)]
pub struct ScenarioExpect {
    pub path: String,
    pub kind: ExpectKind,
}

#[derive(Clone)]
pub enum ExpectKind {
    Equals(Value),
    OneOf(Vec<Value>),
    NonEmpty,
}

#[derive(Clone)]
pub struct Scenario {
    pub id: String,
    pub platform: Option<String>,
    pub command: Option<String>,
    pub expects: Vec<ScenarioExpect>,
}

#[derive(Clone)]
pub struct ScenarioResult {
    pub id: String,
    pub verdict: String,
    pub detail: String,
}

fn load_file(path: &PathBuf) -> Option<Scenario> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: toml::Value = toml::from_str(&text).ok()?;
    let id = v.get("id")?.as_str()?.to_string();
    let platform = v
        .get("given")
        .and_then(|g| g.get("platform"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let command = v
        .get("when")?
        .get("command")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let expects = v
        .get("expect")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let path = e.get("field")?.as_str()?.to_string();
                    let kind = if let Some(x) = e.get("equals") {
                        ExpectKind::Equals(toml_scalar_to_json(x))
                    } else if let Some(list) = e.get("one_of").and_then(toml::Value::as_array) {
                        ExpectKind::OneOf(list.iter().map(toml_scalar_to_json).collect())
                    } else if e.get("non_empty").and_then(toml::Value::as_bool) == Some(true) {
                        ExpectKind::NonEmpty
                    } else {
                        return None;
                    };
                    Some(ScenarioExpect { path, kind })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Scenario {
        id,
        platform,
        command,
        expects,
    })
}

fn toml_scalar_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        _ => Value::Null,
    }
}

/// Load all scenario files under scenarios/<subdir>/.
pub fn load_all(scenarios_dir: &Path, subdirs: &[&str]) -> Vec<Scenario> {
    let mut out = Vec::new();
    for sub in subdirs {
        let dir = scenarios_dir.join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            if let Some(s) = load_file(&f) {
                out.push(s);
            }
        }
    }
    out
}

/// Evaluate a scenario against a command's JSON output.
fn evaluate(scenario: &Scenario, output: &Value) -> Result<(), String> {
    for expect in &scenario.expects {
        let actual = get_path(output, &expect.path);
        let ok = match &expect.kind {
            ExpectKind::Equals(expected) => actual == Some(expected),
            ExpectKind::OneOf(values) => actual.is_some_and(|a| values.iter().any(|v| v == a)),
            ExpectKind::NonEmpty => actual.is_some_and(|a| match a {
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                Value::Null => false,
                _ => true,
            }),
        };
        if !ok {
            return Err(format!(
                "expect {}.{} failed (actual: {})",
                scenario.id,
                expect.path,
                actual
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "<missing>".to_string())
            ));
        }
    }
    Ok(())
}

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Run a [when].command, resolving "nexus-harness" to the current executable so
/// the harness can self-host its own scenario gate.
fn run_command(command: &str) -> (String, String) {
    let mut parts = command.split_whitespace();
    let program = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();
    let program = if program == "nexus-harness" {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        program.to_string()
    };
    let out = Command::new(&program).args(&args).output();
    match out {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            (o.status.success().to_string(), text)
        }
        Err(e) => (false.to_string(), format!("cannot run {program}: {e}")),
    }
}

/// Run all command-scenarios in the given subdirs; static ones are recorded
/// UNKNOWN. Returns (results, gate) — gate is FAIL if any scenario FAIL.
pub fn run_gate(config: &Config, gate_name: &str, subdirs: &[&str]) -> (Vec<ScenarioResult>, Gate) {
    let scenarios = load_all(&config.scenarios_dir, subdirs);
    if scenarios.is_empty() {
        return (
            Vec::new(),
            Gate::ok(gate_name, "no scenario files declared"),
        );
    }
    let mut results: Vec<ScenarioResult> = Vec::new();
    let mut failed = false;
    for s in &scenarios {
        if let Some(plat) = &s.platform {
            let current_plat = if cfg!(windows) {
                "windows"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "macos") {
                "macos"
            } else {
                "other"
            };
            if plat != current_plat {
                results.push(ScenarioResult {
                    id: s.id.clone(),
                    verdict: "UNKNOWN".to_string(),
                    detail: format!("platform contract ({plat} required, host is {current_plat})"),
                });
                continue;
            }
        }
        match &s.command {
            None => results.push(ScenarioResult {
                id: s.id.clone(),
                verdict: "UNKNOWN".to_string(),
                detail: "static contract, runtime not exercisable by harness (no [when].command)"
                    .to_string(),
            }),
            Some(cmd) => {
                let (_, out) = run_command(cmd);
                match serde_json::from_str::<Value>(&out) {
                    Ok(json) => match evaluate(s, &json) {
                        Ok(()) => results.push(ScenarioResult {
                            id: s.id.clone(),
                            verdict: "PASS".to_string(),
                            detail: format!(
                                "command ran, all {} expectations held",
                                s.expects.len()
                            ),
                        }),
                        Err(e) => {
                            failed = true;
                            results.push(ScenarioResult {
                                id: s.id.clone(),
                                verdict: "FAIL".to_string(),
                                detail: e,
                            });
                        }
                    },
                    Err(e) => {
                        failed = true;
                        results.push(ScenarioResult {
                            id: s.id.clone(),
                            verdict: "FAIL".to_string(),
                            detail: format!("output not JSON ({e}): {}", out.trim()),
                        });
                    }
                }
            }
        }
    }
    let detail: Vec<String> = results
        .iter()
        .map(|r| format!("{}: {} ({})", r.id, r.verdict, r.detail))
        .collect();
    let detail = detail.join("\n");
    if failed {
        (results.clone(), Gate::fail(gate_name, &detail))
    } else {
        (results, Gate::ok(gate_name, &detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scenario(expects: Vec<ScenarioExpect>) -> Scenario {
        Scenario {
            id: "t".to_string(),
            platform: None,
            command: None,
            expects,
        }
    }

    #[test]
    fn get_path_nested_and_array() {
        let v = json!({"a": {"b": [10, 20]}});
        assert_eq!(get_path(&v, "a.b.1"), Some(&json!(20)));
        assert_eq!(get_path(&v, "a.b.2"), None);
        assert_eq!(get_path(&v, "missing"), None);
    }

    #[test]
    fn evaluate_equals() {
        let s = scenario(vec![ScenarioExpect {
            path: "verdict".to_string(),
            kind: ExpectKind::Equals(json!("PASS")),
        }]);
        assert!(evaluate(&s, &json!({"verdict": "PASS"})).is_ok());
        assert!(evaluate(&s, &json!({"verdict": "FAIL"})).is_err());
    }

    #[test]
    fn evaluate_one_of_and_non_empty() {
        let s = scenario(vec![
            ScenarioExpect {
                path: "verdict".to_string(),
                kind: ExpectKind::OneOf(vec![json!("PASS"), json!("UNKNOWN")]),
            },
            ScenarioExpect {
                path: "evidence.id".to_string(),
                kind: ExpectKind::NonEmpty,
            },
        ]);
        assert!(
            evaluate(
                &s,
                &json!({"verdict": "UNKNOWN", "evidence": {"id": "abc"}})
            )
            .is_ok()
        );
        assert!(evaluate(&s, &json!({"verdict": "FAIL", "evidence": {"id": "abc"}})).is_err());
        assert!(evaluate(&s, &json!({"verdict": "PASS", "evidence": {"id": ""}})).is_err());
        assert!(evaluate(&s, &json!({"verdict": "PASS"})).is_err());
    }

    #[test]
    fn evaluate_numbers_compare_as_numbers() {
        let s = scenario(vec![ScenarioExpect {
            path: "schema_version".to_string(),
            kind: ExpectKind::Equals(json!(1)),
        }]);
        assert!(evaluate(&s, &json!({"schema_version": 1})).is_ok());
    }
}
