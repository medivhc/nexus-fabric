//! Load machine configuration: harness.toml paths + policies/quality.toml gates.

use crate::env::Repo;
use serde_json::Value;
use std::path::PathBuf;

pub struct Config {
    pub policies_dir: PathBuf,
    pub scenarios_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub crates_dir: PathBuf,
    pub engineering_dir: PathBuf,
    /// policies/quality.toml (gate lists for fast/full verification).
    pub quality: Value,
}

fn toml_file_to_json(path: PathBuf, what: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {what} at {}: {e}", path.display()))?;
    let v: toml::Value = toml::from_str(&text)
        .map_err(|e| format!("cannot parse {what} at {}: {e}", path.display()))?;
    Ok(toml_to_json(&v))
}

/// Convert toml::Value into serde_json::Value (no serde derive dependency).
fn toml_to_json(v: &toml::Value) -> Value {
    use toml::Value as T;
    match v {
        T::String(s) => Value::String(s.clone()),
        T::Integer(i) => Value::from(*i),
        T::Float(f) => Value::from(*f),
        T::Boolean(b) => Value::from(*b),
        T::Datetime(d) => Value::String(d.to_string()),
        T::Array(a) => Value::Array(a.iter().map(toml_to_json).collect()),
        T::Table(t) => Value::Object(
            t.iter()
                .map(|(k, x)| (k.clone(), toml_to_json(x)))
                .collect(),
        ),
    }
}

impl Config {
    pub fn load(repo: &Repo) -> Result<Config, String> {
        let harness = toml_file_to_json(repo.resolve("harness.toml"), "harness.toml")?;
        let get = |key: &str| -> Result<String, String> {
            harness
                .pointer(&format!("/paths/{key}"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("harness.toml missing [paths].{key}"))
        };
        let policies_dir = repo.resolve(&get("policies")?);
        let scenarios_dir = repo.resolve(&get("scenarios")?);
        let evidence_dir = repo.resolve(&get("evidence")?);
        let crates_dir = repo.resolve(&get("crates")?);
        let engineering_dir = repo.resolve(&get("engineering")?);
        let quality =
            toml_file_to_json(policies_dir.join("quality.toml"), "policies/quality.toml")?;
        Ok(Config {
            policies_dir,
            scenarios_dir,
            evidence_dir,
            crates_dir,
            engineering_dir,
            quality,
        })
    }

    /// Gate names declared by policies/quality.toml for the given level.
    pub fn declared_gates(&self, level: &str) -> Vec<String> {
        self.quality
            .pointer(&format!("/verification/{level}/gates"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}
