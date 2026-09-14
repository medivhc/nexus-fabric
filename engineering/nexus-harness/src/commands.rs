//! Command implementations: status / context / check / test / verify / explain.

use crate::config::Config;
use crate::env::Repo;
use crate::evidence::{self, Bindings};
use crate::gates::{self, Gate};
use crate::scenario::ScenarioResult;
use serde_json::{Value, json};

type Outcome = (String, String, Vec<(String, Value)>);

fn gates_json(gates: &[Gate]) -> Value {
    json!(
        gates
            .iter()
            .map(|g| json!({"name": g.name, "verdict": g.verdict, "detail": g.detail}))
            .collect::<Vec<_>>()
    )
}

fn setup() -> Result<(Repo, Config), Outcome> {
    let repo = Repo::discover().map_err(|e| {
        (
            "BLOCKED".to_string(),
            e,
            vec![("evidence".to_string(), json!({"available": false}))],
        )
    })?;
    let config = Config::load(&repo).map_err(|e| {
        (
            "BLOCKED".to_string(),
            e,
            vec![("evidence".to_string(), json!({"available": false}))],
        )
    })?;
    Ok((repo, config))
}

pub fn status() -> Outcome {
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let bindings = Bindings::current(&repo);
    let latest = evidence::read_latest_summary(&config);

    let (verdict, message, extra) = match &latest {
        None => (
            "UNKNOWN".to_string(),
            "no evidence recorded; run nexus-harness verify --fast".to_string(),
            json!({"available": false}),
        ),
        Some(l) => {
            let latest_verdict = l
                .get("verdict")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN");
            let latest_bindings = l.get("bindings").cloned().unwrap_or(Value::Null);
            let fresh = bindings.same_as(&latest_bindings);
            let id = l
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let dir = if id.is_empty() {
                String::new()
            } else {
                format!("verify-{id}")
            };
            let ev = json!({"available": true, "id": id, "dir": dir, "verdict": latest_verdict});
            if !fresh {
                (
                    "STALE".to_string(),
                    format!(
                        "latest evidence ({id}) bindings differ from current state; refresh with nexus-harness verify"
                    ),
                    ev,
                )
            } else if latest_verdict == "PASS" {
                (
                    "PASS".to_string(),
                    format!("latest evidence ({id}) is fresh and PASS"),
                    ev,
                )
            } else {
                (
                    "UNKNOWN".to_string(),
                    format!(
                        "latest evidence ({id}) is fresh but verdict is {latest_verdict}; run nexus-harness verify to refresh"
                    ),
                    ev,
                )
            }
        }
    };

    let mut extras = vec![
        ("evidence".to_string(), extra),
        ("bindings".to_string(), bindings.to_json()),
    ];
    extras.extend(latest.iter().flat_map(|l| {
        l.get("message")
            .map(|m| ("evidence_message".to_string(), m.clone()))
    }));
    (verdict, message, extras)
}

pub fn context(target: &str) -> Outcome {
    if target.is_empty() {
        return (
            "BLOCKED".to_string(),
            "usage: nexus-harness context <target>".to_string(),
            Vec::new(),
        );
    }
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };

    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let t = std::path::Path::new(target);
    if t.is_absolute() || target.contains('/') || target.contains('\\') {
        dirs.push(repo.resolve(target));
    } else {
        for base in [
            &config.crates_dir,
            &config.engineering_dir,
            &repo.root.join("apps"),
        ] {
            dirs.push(base.join(target));
        }
    }
    let found = dirs.into_iter().find(|d| d.is_dir());

    match found {
        Some(dir) => {
            let contract = dir.join("MODULE.md");
            let headings: Vec<String> = std::fs::read_to_string(&contract)
                .map(|text| {
                    text.lines()
                        .filter(|l| l.starts_with("## "))
                        .map(|l| l.trim_start_matches("## ").to_string())
                        .collect()
                })
                .unwrap_or_default();
            let mapped = mapped_scenarios(&config, target);
            (
                "PASS".to_string(),
                format!(
                    "context for {target}: module contract + {} mapped scenario(s)",
                    mapped.len()
                ),
                vec![
                    (
                        "module_contract".to_string(),
                        json!(contract.to_string_lossy()),
                    ),
                    ("headings".to_string(), json!(headings)),
                    ("mapped_scenarios".to_string(), json!(mapped)),
                ],
            )
        }
        None => (
            "BLOCKED".to_string(),
            format!("target not found: {target} (looked in crates/, apps/, engineering/)"),
            Vec::new(),
        ),
    }
}

/// Scenarios whose id or requirement references the target name.
fn mapped_scenarios(config: &Config, target: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(top) = std::fs::read_dir(&config.scenarios_dir) else {
        return out;
    };
    let mut subs: Vec<String> = top
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    subs.sort();
    for sub in subs {
        let dir = config.scenarios_dir.join(&sub);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        files.sort();
        for f in files {
            if let Ok(text) = std::fs::read_to_string(dir.join(&f)) {
                if text.contains(target) {
                    out.push(format!("{sub}/{f}"));
                }
            }
        }
    }
    out
}

pub fn check() -> Outcome {
    let (repo, _config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let gates = vec![
        gates::whitespace_gate(&repo),
        gates::format_gate(&repo),
        gates::check_gate(&repo),
        gates::clippy_gate(&repo),
    ];
    aggregate("check", &gates)
}

pub fn test_affected() -> Outcome {
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let gate = gates::affected_tests_gate(&repo, &config);
    let verdict = gate.verdict.clone();
    let message = gate.detail.clone();
    let extras = vec![("gates".to_string(), gates_json(&[gate]))];
    (verdict, message, extras)
}

pub fn verify(sub: &str) -> Outcome {
    let mode = match sub {
        "" | "--fast" => "fast",
        "--full" => "full",
        _ => {
            return (
                "BLOCKED".to_string(),
                "usage: nexus-harness verify [--fast|--full]".to_string(),
                Vec::new(),
            );
        }
    };
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let bindings = Bindings::current(&repo);

    // Gates are driven by policies/quality.toml declarations (single source of
    // truth); declared-but-unimplemented gates surface as UNKNOWN, never skipped.
    let mut gates: Vec<Gate> = vec![gates::whitespace_gate(&repo)];
    for name in config.declared_gates("fast") {
        gates.push(match name.as_str() {
            "format" => gates::format_gate(&repo),
            "check" => gates::check_gate(&repo),
            "clippy" => gates::clippy_gate(&repo),
            "architecture-delta" => gates::architecture_gate(&config),
            "dependency-delta" => gates::dependency_gate(&repo, &config),
            "affected-tests" => gates::affected_tests_gate(&repo, &config),
            "selected-properties" => gates::selected_properties_gate(&repo),
            other => gates::unimplemented(other),
        });
    }
    let mut scenarios: Vec<ScenarioResult> = Vec::new();

    if mode == "full" {
        for name in config.declared_gates("full") {
            gates.push(match name.as_str() {
                "workspace-tests" => gates::workspace_tests_gate(&repo),
                "integration" => gates::integration_gate(&repo),
                "product-scenarios" => {
                    let (sr, g) =
                        scenario_run(&config, "product-scenarios", &["product", "engineering"]);
                    scenarios.extend(sr);
                    g
                }
                "regression" => {
                    let (sr, g) = scenario_run(&config, "regression", &["regression"]);
                    scenarios.extend(sr);
                    g
                }
                "architecture-policy" => gates::architecture_gate(&config),
                "dependency-governance" => gates::dependency_gate(&repo, &config),
                "coverage-summary" => gates::coverage_gate(&repo),
                "selected-fuzz" => gates::fuzz_gate(&repo),
                "selected-concurrency" => gates::concurrency_gate(&repo),
                "performance-budgets" => gates::performance_budgets_gate(&config),
                "platform-checks" => gates::platform_checks_gate(&config),
                "feature-matrix" => gates::feature_matrix_gate(&repo),
                "portable-core" => gates::portable_core_gate(&repo, &config),
                other => gates::unimplemented(other),
            });
        }
    }

    let failed: Vec<&Gate> = gates.iter().filter(|g| g.verdict == "FAIL").collect();
    let unknown = gates.iter().filter(|g| g.verdict == "UNKNOWN").count();
    let (verdict, message) = if failed.is_empty() {
        (
            "PASS".to_string(),
            format!(
                "{mode} verify: {} gates, {} pass, 0 fail, {unknown} unknown",
                gates.len(),
                gates.len() - unknown
            ),
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "{mode} verify: {} gate(s) failed: {}",
                failed.len(),
                failed
                    .iter()
                    .map(|g| g.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };

    let id = match evidence::write_evidence(
        &repo, &config, &verdict, &message, &gates, &scenarios, &bindings,
    ) {
        Ok(id) => id,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("evidence write failed: {e}"),
                vec![("gates".to_string(), gates_json(&gates))],
            );
        }
    };

    let extras = vec![
        ("gates".to_string(), gates_json(&gates)),
        (
            "evidence".to_string(),
            json!({"id": id, "dir": format!("verify-{id}"), "verdict": verdict, "bindings": bindings.to_json()}),
        ),
    ];
    (verdict, message, extras)
}

fn scenario_run(config: &Config, gate_name: &str, subdirs: &[&str]) -> (Vec<ScenarioResult>, Gate) {
    crate::scenario::run_gate(config, gate_name, subdirs)
}

pub fn explain() -> Outcome {
    let (_repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let Some(dir) = evidence::latest_dir(&config) else {
        return (
            "UNKNOWN".to_string(),
            "no evidence recorded; run nexus-harness verify --fast".to_string(),
            Vec::new(),
        );
    };
    let id = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let text = match std::fs::read_to_string(dir.join("gates.json")) {
        Ok(t) => t,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("cannot read {}: {e}", dir.join("gates.json").display()),
                Vec::new(),
            );
        }
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return (
            "BLOCKED".to_string(),
            "gates.json is malformed".to_string(),
            Vec::new(),
        );
    };
    let mut failing: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for g in value
        .get("gates")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
    {
        let name = g
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let verdict = g.get("verdict").and_then(Value::as_str).unwrap_or("?");
        if verdict == "FAIL" {
            failing.push(format!(
                "{name}: {}",
                g.get("detail").and_then(Value::as_str).unwrap_or("")
            ));
        } else if verdict == "UNKNOWN" {
            unknown.push(name);
        }
    }
    let (verdict, message) = if !failing.is_empty() {
        (
            "FAIL".to_string(),
            format!(
                "evidence {id}: {} gate(s) failed; fix and re-run nexus-harness verify",
                failing.len()
            ),
        )
    } else if !unknown.is_empty() {
        (
            "UNKNOWN".to_string(),
            format!(
                "evidence {id}: no failures; {} gate(s) unimplemented",
                unknown.len()
            ),
        )
    } else {
        (
            "PASS".to_string(),
            format!("evidence {id}: no failures recorded"),
        )
    };
    (
        verdict,
        message,
        vec![
            ("evidence_id".to_string(), json!(id)),
            ("failing_gates".to_string(), json!(failing)),
            ("unimplemented_gates".to_string(), json!(unknown)),
        ],
    )
}

fn aggregate(cmd: &str, gates: &[Gate]) -> Outcome {
    let failed: Vec<&Gate> = gates.iter().filter(|g| g.verdict == "FAIL").collect();
    if failed.is_empty() {
        (
            "PASS".to_string(),
            format!("{cmd}: {} gate(s) passed", gates.len()),
            vec![("gates".to_string(), gates_json(gates))],
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "{cmd}: {} gate(s) failed: {}",
                failed.len(),
                failed
                    .iter()
                    .map(|g| g.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            vec![("gates".to_string(), gates_json(gates))],
        )
    }
}
