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

/// verify-<id> short id: first 12 chars of hash(revision|config|contract),
/// namespaced by the current agent (env `NEXUS_AGENT`) so multiple agents
/// working on the same revision do not overwrite each other's evidence.
pub fn verify_id(repo: &Repo, b: &Bindings) -> String {
    let seed = format!(
        "{}\n{}\n{}",
        b.source_revision, b.configuration_digest, b.contract_hash
    );
    let h = repo
        .hash_stdin(&seed)
        .unwrap_or_else(|_| "unknown".to_string());
    let short = if h.len() > 12 { &h[..12] } else { h.as_str() };
    format_verify_id(agent_tag().as_deref(), short)
}

/// `verify-<agent>-<hash>` when an agent tag is present, else `verify-<hash>`.
fn format_verify_id(agent: Option<&str>, hash: &str) -> String {
    match agent {
        Some(a) => format!("{a}-{hash}"),
        None => hash.to_string(),
    }
}

/// Agent tag from env `NEXUS_AGENT` (sanitized: `[A-Za-z0-9_-]{1,32}`).
/// Absent/invalid → `None` (single-agent / CI compatible behaviour).
pub fn agent_tag() -> Option<String> {
    let raw = std::env::var("NEXUS_AGENT").ok()?;
    if raw.is_empty() || raw.len() > 32 {
        return None;
    }
    raw.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        .then_some(raw)
}

/// Does this evidence dir name belong to the given agent scope?
/// - Some(agent): names must be `verify-<agent>-<rest>`.
/// - None: legacy names `verify-<hash>` only (no extra `-` segment).
fn dir_belongs_to_agent(name: &str, agent: Option<&str>) -> bool {
    let Some(rest) = name.strip_prefix("verify-") else {
        return false;
    };
    match agent {
        Some(a) => rest.starts_with(&format!("{a}-")),
        None => !rest.contains('-'),
    }
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

    mark_stale_others(config, &id, &bindings.to_json(), agent_tag().as_deref())?;

    let latest = json!({"id": id, "dir": format!("verify-{id}"), "verdict": verdict});
    write_json(&config.evidence_dir.join("latest.json"), &latest)?;
    Ok(id)
}

/// Prior verify dirs **of the same agent scope** whose bindings differ from
/// current become STALE. Cross-agent evidence is left untouched: Agent B's
/// verify run must not invalidate Agent A's evidence.
fn mark_stale_others(
    config: &Config,
    current_id: &str,
    current_bindings: &Value,
    agent: Option<&str>,
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
        if !name.starts_with("verify-")
            || name == format!("verify-{current_id}")
            || !dir_belongs_to_agent(&name, agent)
        {
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

/// 单场景运行的证据 id：`scenario-<agent>-<hash>`。
/// hash = hash(revision | scenario_id | configuration | contract) 前 12 hex，
/// 与 verify 证据同命名空间规则（NEXUS_AGENT），目录即 `.evidence/<id>/`，
/// 与 `verify-*` 目录互不干扰。
pub fn scenario_run_id(repo: &Repo, b: &Bindings, scenario_id: &str) -> String {
    let seed = format!(
        "{}\n{}\n{}\n{}",
        b.source_revision, scenario_id, b.configuration_digest, b.contract_hash
    );
    let h = repo
        .hash_stdin(&seed)
        .unwrap_or_else(|_| "unknown".to_string());
    let short = if h.len() > 12 { &h[..12] } else { h.as_str() };
    match agent_tag() {
        Some(a) => format!("scenario-{a}-{short}"),
        None => format!("scenario-{short}"),
    }
}

/// `write_scenario_evidence` 的参数包（避免函数参数过多 + 调用点可读）。
pub struct ScenarioEvidence<'a> {
    pub scenario_id: &'a str,
    pub verdict: &'a str,
    pub message: &'a str,
    pub failure_signature: &'a Value,
    pub duration_ms: u64,
}

/// 写单场景运行证据：`.evidence/scenario-<id>/summary.json`。
///
/// 场景证据是诊断性记录：**不**参与 STALE 扫荡、**不**写 `latest.json`，
/// verify 门禁证据不受影响。调用方凭返回的 evidence_id 直接引用。
pub fn write_scenario_evidence(
    repo: &Repo,
    config: &Config,
    ev: &ScenarioEvidence,
    bindings: &Bindings,
) -> Result<String, String> {
    let id = scenario_run_id(repo, bindings, ev.scenario_id);
    let dir = config.evidence_dir.join(&id);
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;

    let summary = json!({
        "schema_version": 1,
        "command": "scenario run",
        "scenario": ev.scenario_id,
        "verdict": ev.verdict,
        "message": ev.message,
        "id": id,
        "failure_signature": ev.failure_signature,
        "duration_ms": ev.duration_ms,
        "bindings": bindings.to_json(),
    });
    write_json(&dir.join("summary.json"), &summary)?;
    write_json(
        &dir.join("metadata.json"),
        &json!({"bindings": bindings.to_json(), "env": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }}),
    )?;
    Ok(id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bindings(rev: &str) -> Bindings {
        Bindings {
            source_revision: rev.to_string(),
            working_tree_digest: "wt".to_string(),
            dirty_state: false,
            configuration_digest: "cfg".to_string(),
            feature_set: vec!["f".to_string()],
            target_triple: "t".to_string(),
            toolchain_version: "1.0".to_string(),
            harness_schema_version: 1,
            platform_capability_digest: "p".to_string(),
            contract_hash: "c".to_string(),
        }
    }

    #[test]
    fn same_as_true_for_equal_bindings() {
        let a = bindings("r1");
        assert!(a.same_as(&a.to_json()));
    }

    #[test]
    fn same_as_false_for_different_revision() {
        assert!(!bindings("r1").same_as(&bindings("r2").to_json()));
    }

    #[test]
    fn verify_id_deterministic() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let a = bindings("r1");
        assert_eq!(verify_id(&repo, &a), verify_id(&repo, &a));
        assert_ne!(verify_id(&repo, &a), verify_id(&repo, &bindings("r2")));
    }

    #[test]
    fn stale_marking_detects_binding_change() {
        let tmp = std::env::temp_dir().join(format!("nexus-ev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config = Config {
            policies_dir: tmp.join("policies"),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.clone(),
            crates_dir: tmp.join("crates"),
            engineering_dir: tmp.join("engineering"),
            quality: json!({}),
            portable_core: vec![],
        };
        let old_dir = tmp.join("verify-old");
        std::fs::create_dir_all(&old_dir).unwrap();
        let write = |v: &Value| {
            std::fs::write(
                old_dir.join("summary.json"),
                serde_json::to_string(v).unwrap(),
            )
            .unwrap()
        };

        write(
            &json!({"schema_version": 1, "command": "verify", "verdict": "PASS",
                      "id": "old", "bindings": bindings("old-rev").to_json()}),
        );
        mark_stale_others(&config, "current", &bindings("new-rev").to_json(), None).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(old_dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(v["verdict"], json!("STALE"));

        write(
            &json!({"schema_version": 1, "command": "verify", "verdict": "PASS",
                      "id": "old", "bindings": bindings("same-rev").to_json()}),
        );
        mark_stale_others(&config, "current", &bindings("same-rev").to_json(), None).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(old_dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(v["verdict"], json!("PASS"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn verify_id_is_namespaced_by_agent() {
        assert_eq!(format_verify_id(None, "abcdef123456"), "abcdef123456");
        assert_eq!(
            format_verify_id(Some("agent-a"), "abcdef123456"),
            "agent-a-abcdef123456"
        );
    }

    #[test]
    fn dir_belongs_to_agent_matches_scope() {
        assert!(dir_belongs_to_agent(
            "verify-agent-a-abc123",
            Some("agent-a")
        ));
        assert!(!dir_belongs_to_agent(
            "verify-agent-b-abc123",
            Some("agent-a")
        ));
        assert!(!dir_belongs_to_agent("verify-agent-a-abc123", None));
        assert!(dir_belongs_to_agent("verify-abc123", None));
        assert!(!dir_belongs_to_agent("review-agent-a-r1", Some("agent-a")));
    }

    #[test]
    fn stale_marking_is_scoped_to_same_agent() {
        let tmp = std::env::temp_dir().join(format!("nexus-ev-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config = Config {
            policies_dir: tmp.join("policies"),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.clone(),
            crates_dir: tmp.join("crates"),
            engineering_dir: tmp.join("engineering"),
            quality: json!({}),
            portable_core: vec![],
        };
        let write_summary = |dir: &str, id: &str, rev: &str| {
            let d = tmp.join(format!("verify-{dir}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("summary.json"),
                serde_json::to_string(&json!({
                    "schema_version": 1, "command": "verify", "verdict": "PASS",
                    "id": id, "bindings": bindings(rev).to_json(),
                }))
                .unwrap(),
            )
            .unwrap();
        };
        // Agent A 与 Agent B 各有一条旧证据（不同 revision）。
        write_summary("agent-a-old", "agent-a-old", "rev-a-old");
        write_summary("agent-b-old", "agent-b-old", "rev-b-old");

        // 以 Agent A 的新 revision 跑 mark_stale_others（agent 作为参数传入）。
        let result = mark_stale_others(
            &config,
            "agent-a-new",
            &bindings("rev-a-new").to_json(),
            Some("agent-a"),
        );
        result.unwrap();

        let read_verdict = |dir: &str| -> String {
            let text =
                std::fs::read_to_string(tmp.join(format!("verify-{dir}/summary.json"))).unwrap();
            let v: Value = serde_json::from_str(&text).unwrap();
            v["verdict"].as_str().unwrap_or("?").to_string()
        };
        // 同 agent 的旧证据被标 STALE；跨 agent 的保持 PASS。
        assert_eq!(read_verdict("agent-a-old"), "STALE");
        assert_eq!(read_verdict("agent-b-old"), "PASS");

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
