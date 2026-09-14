//! Evidence store: write/read .evidence/verify-<id>/, freshness binding,
//! STALE marking (surfaced to .githooks/pre-push).

use crate::config::Config;
use crate::env::Repo;
use crate::gates::Gate;
use crate::scenario::ScenarioResult;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

pub struct Bindings {
    pub source_revision: String,
    pub working_tree_digest: String,
    pub dirty_state: bool,
    pub configuration_digest: String,
    pub feature_set: Vec<String>,
    pub target_triple: String,
    pub toolchain_version: String,
    pub harness_schema_version: u32,
    pub platform_capability_digest: String,
    pub contract_hash: String,
}

impl Bindings {
    pub fn current(repo: &Repo) -> Bindings {
        let (toolchain, target) = crate::env::toolchain();
        Bindings {
            source_revision: repo.revision(),
            working_tree_digest: repo.working_tree_digest(),
            dirty_state: repo.is_dirty(),
            configuration_digest: repo.configuration_digest(),
            feature_set: vec!["workspace:default".to_string()],
            target_triple: target,
            toolchain_version: toolchain,
            harness_schema_version: 1,
            platform_capability_digest: crate::env::platform_digest(repo),
            contract_hash: repo.contract_hash(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "source_revision": self.source_revision,
            "working_tree_digest": self.working_tree_digest,
            "dirty_state": self.dirty_state,
            "configuration_digest": self.configuration_digest,
            "feature_set": self.feature_set,
            "target_triple": self.target_triple,
            "toolchain_version": self.toolchain_version,
            "harness_schema_version": self.harness_schema_version,
            "platform_capability_digest": self.platform_capability_digest,
            "contract_hash": self.contract_hash,
        })
    }

    pub fn same_as(&self, other: &Value) -> bool {
        self.to_json() == *other
    }
}

/// verify-<id> short id: first 12 chars of hash(revision|config|contract).
pub fn verify_id(repo: &Repo, b: &Bindings) -> String {
    let seed = format!(
        "{}\n{}\n{}",
        b.source_revision, b.configuration_digest, b.contract_hash
    );
    let h = repo
        .hash_stdin(&seed)
        .unwrap_or_else(|_| "unknown".to_string());
    if h.len() > 12 { h[..12].to_string() } else { h }
}

fn write_json(path: &PathBuf, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("serialize: {e}"))?;
    fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Write full evidence for a verify run; marks prior evidence with differing
/// bindings as STALE; refreshes .evidence/latest.json.
pub fn write_evidence(
    repo: &Repo,
    config: &Config,
    verdict: &str,
    message: &str,
    gates: &[Gate],
    scenarios: &[ScenarioResult],
    bindings: &Bindings,
) -> Result<String, String> {
    let id = verify_id(repo, bindings);
    let dir = config.evidence_dir.join(format!("verify-{id}"));
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;

    let summary = json!({
        "schema_version": 1,
        "command": "verify",
        "verdict": verdict,
        "message": message,
        "id": id,
        "bindings": bindings.to_json(),
    });
    let gates_json: Vec<Value> = gates
        .iter()
        .map(|g| json!({"name": g.name, "verdict": g.verdict, "detail": g.detail}))
        .collect();
    let scenarios_json: Vec<Value> = scenarios
        .iter()
        .map(|s| json!({"id": s.id, "verdict": s.verdict, "detail": s.detail}))
        .collect();
    let checks = json!({"gates": gates_json, "scenarios": scenarios_json});

    write_json(&dir.join("summary.json"), &summary)?;
    write_json(&dir.join("gates.json"), &checks)?;
    write_json(
        &dir.join("metadata.json"),
        &json!({"bindings": bindings.to_json(), "env": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }}),
    )?;

    mark_stale_others(config, &id, &bindings.to_json())?;

    let latest = json!({"id": id, "dir": format!("verify-{id}"), "verdict": verdict});
    write_json(&config.evidence_dir.join("latest.json"), &latest)?;
    Ok(id)
}

/// Prior verify dirs whose bindings differ from current become STALE.
fn mark_stale_others(
    config: &Config,
    current_id: &str,
    current_bindings: &Value,
) -> Result<(), String> {
    let Ok(entries) = fs::read_dir(&config.evidence_dir) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let dir = e.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !name.starts_with("verify-") || name == format!("verify-{current_id}") {
            continue;
        }
        let summary_path = dir.join("summary.json");
        let Ok(text) = fs::read_to_string(&summary_path) else {
            continue;
        };
        let Ok(mut summary) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let bindings = summary.get("bindings").cloned().unwrap_or(Value::Null);
        if bindings != *current_bindings
            && summary.get("verdict").and_then(Value::as_str) != Some("STALE")
        {
            summary["verdict"] = json!("STALE");
            summary["message"] = json!(
                "bindings changed since this evidence was produced; refresh with nexus-harness verify"
            );
            write_json(&summary_path, &summary)?;
        }
    }
    Ok(())
}

/// Read .evidence/latest.json (None if absent/unreadable).
pub fn read_latest(config: &Config) -> Option<Value> {
    let path = config.evidence_dir.join("latest.json");
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

/// Read the full summary.json of the latest evidence run (bindings included).
pub fn read_latest_summary(config: &Config) -> Option<Value> {
    let dir = latest_dir(config)?;
    let text = fs::read_to_string(dir.join("summary.json")).ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

/// Dir of the latest evidence run.
pub fn latest_dir(config: &Config) -> Option<PathBuf> {
    let latest = read_latest(config)?;
    let dir = latest.get("dir")?.as_str()?;
    Some(config.evidence_dir.join(dir))
}
