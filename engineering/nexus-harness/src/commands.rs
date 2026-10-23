//! Command implementations: status / context / check / test / verify / explain.

use crate::config::{Config, ScenarioTimeouts, VerifyTimeouts};
use crate::env::Repo;
use crate::evidence::{self, Bindings};
use crate::gates::{self, Gate, GateBudget};
use crate::scenario::{ScenarioArtifacts, ScenarioResult};
use serde_json::{Value, json};

type Outcome = (String, String, Vec<(String, Value)>);

fn gates_json(gates: &[Gate]) -> Value {
    json!(
        gates
            .iter()
            .map(|g| json!({
                "name": g.name,
                "verdict": g.verdict,
                "detail": g.detail,
                "duration_ms": g.duration_ms,
                "timed_out": g.timed_out,
                "skipped_by_deadline": g.skipped_by_deadline,
            }))
            .collect::<Vec<_>>()
    )
}

pub(crate) fn setup() -> Result<(Repo, Config), Outcome> {
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
    let bindings = Bindings::current(&repo, &config);
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

pub fn context(args: &[String]) -> Outcome {
    // `context <target> [--provider-binary <path>]`。`--provider-binary` 存在的唯一理由
    // 是让"provider 不可用"这条降级路径可被 E4 确定性地演练（MODULE.md 不变量 6）：
    // 它不接受写能力参数，也不改变任何既有字段语义。
    let mut target = String::new();
    let mut provider_override: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--provider-binary" {
            provider_override = args.get(index + 1).cloned();
            index += 2;
            continue;
        }
        if !arg.starts_with("--") && target.is_empty() {
            target = arg.to_string();
        }
        index += 1;
    }
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
    let t = std::path::Path::new(&target);
    if t.is_absolute() || target.contains('/') || target.contains('\\') {
        dirs.push(repo.resolve(&target));
    } else {
        for base in [
            &config.crates_dir,
            &config.engineering_dir,
            &repo.root.join("apps"),
        ] {
            dirs.push(base.join(&target));
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
            let mapped = mapped_scenarios(&config, &target);
            // Phase 2：附加**有界**语义锚点。语义层的任何结果都不改变上面这些字段，
            // 也不改变 verdict —— 见 MODULE.md「Context Semantic Anchoring」不变量 1。
            let semantic =
                crate::code_intel::anchors(&repo, &config, &dir, provider_override.as_deref());
            let mut extras: Vec<(String, Value)> = vec![
                (
                    "module_contract".to_string(),
                    json!(contract.to_string_lossy()),
                ),
                ("headings".to_string(), json!(headings)),
                ("mapped_scenarios".to_string(), json!(mapped)),
                ("authority".to_string(), json!("advisory")),
                ("semantic_status".to_string(), json!(semantic.status)),
                ("semantic_anchors".to_string(), json!(semantic.anchors)),
                (
                    "semantic_budget".to_string(),
                    json!({
                        "max_results": semantic.max_results,
                        "truncated": semantic.truncated,
                        "candidate_queries": semantic.candidate_queries,
                        "candidate_spans": semantic.candidate_spans,
                        "workspace_scope": semantic.workspace_scope,
                    }),
                ),
                ("snapshot".to_string(), semantic.snapshot),
            ];
            if let Some((code, reason)) = &semantic.reason {
                extras.push((
                    "semantic_reason".to_string(),
                    json!({"code": code, "reason": reason}),
                ));
            }
            (
                "PASS".to_string(),
                format!(
                    "context for {target}: module contract + {} mapped scenario(s) + {} semantic anchor(s) [{}]",
                    mapped.len(),
                    extras_anchor_count(&extras),
                    semantic.status
                ),
                extras,
            )
        }
        None => (
            "BLOCKED".to_string(),
            format!("target not found: {target} (looked in crates/, apps/, engineering/)"),
            Vec::new(),
        ),
    }
}

/// 只用于 message 文案，不参与判定。
fn extras_anchor_count(extras: &[(String, Value)]) -> usize {
    extras
        .iter()
        .find(|(k, _)| k == "semantic_anchors")
        .and_then(|(_, v)| v.as_array())
        .map(Vec::len)
        .unwrap_or(0)
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
        gates::whitespace_gate(&repo, GateBudget::unlimited()),
        gates::format_gate(&repo, GateBudget::unlimited()),
        gates::check_gate(&repo, GateBudget::unlimited()),
        gates::clippy_gate(&repo, GateBudget::unlimited()),
    ];
    aggregate("check", &gates)
}

pub fn test_affected() -> Outcome {
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let gate = gates::affected_tests_gate(&repo, &config, GateBudget::unlimited());
    let verdict = gate.verdict.clone();
    let message = gate.detail.clone();
    let extras = vec![("gates".to_string(), gates_json(&[gate]))];
    (verdict, message, extras)
}

/// Standalone benchmark run: executes the P3.6 perf_bench driver and reports
/// its budget verdict (P3.7). WARN maps to PASS-with-note; run/parse failure
/// => UNKNOWN (never silently passed).
pub fn bench() -> Outcome {
    let (repo, config) = match setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let gate = gates::bench_gate(&repo, &config, GateBudget::unlimited());
    let verdict = gate.verdict.clone();
    let message = gate.detail.clone();
    let extras = vec![(
        "bench".to_string(),
        json!({"gate": gate.name, "verdict": gate.verdict, "detail": gate.detail}),
    )];
    (verdict, message, extras)
}

pub struct VerifyRun {
    pub gates: Vec<Gate>,
    pub scenarios: Vec<ScenarioResult>,
    pub timing: evidence::VerifyTiming,
}

/// 门名序列：`whitespace` + fast 声明 + （full 时）full 声明，顺序不变。
fn gate_sequence(config: &Config, mode: &str) -> Vec<String> {
    let mut names = vec!["whitespace".to_string()];
    names.extend(config.declared_gates("fast"));
    if mode == "full" {
        names.extend(config.declared_gates("full"));
    }
    names
}

/// 串行门编排（可注入，供 AC7/AC8 单测）：
/// - 全局截止已过 → 当前门记 BLOCKED/skipped（duration 0），不再调用 invoke；
/// - 门超时且此刻全局已过期 → 覆写为 BLOCKED/skipped（保留实际 duration）；
/// - 其余原样保留。
fn run_gate_sequence(
    names: &[String],
    global: GateBudget,
    deadline_secs: u64,
    budget_for: &dyn Fn(&str, GateBudget) -> GateBudget,
    invoke: &mut dyn FnMut(&str, GateBudget) -> Gate,
) -> (Vec<Gate>, bool) {
    let mut gates = Vec::new();
    let mut deadline_exceeded = false;
    for name in names {
        if global.expired() {
            deadline_exceeded = true;
            gates.push(Gate::blocked(
                name,
                &format!("not run: full verify deadline ({deadline_secs}s) exceeded"),
            ));
            continue;
        }
        let budget = budget_for(name, global);
        let gate = invoke(name, budget);
        if gate.timed_out && global.expired() {
            let mut blocked = Gate::blocked(
                name,
                &format!(
                    "gate '{name}' interrupted: full verify deadline ({deadline_secs}s) exceeded"
                ),
            );
            blocked.duration_ms = gate.duration_ms;
            deadline_exceeded = true;
            gates.push(blocked);
        } else {
            gates.push(gate);
        }
    }
    (gates, deadline_exceeded)
}

/// 聚合顺序（E1 冻结）：任一 BLOCKED → BLOCKED；否则任一 FAIL → FAIL；否则 PASS。
/// UNKNOWN 仍不阻塞（既有语义）。
fn aggregate_verdict(gates: &[Gate], mode: &str) -> (String, String) {
    let blocked = gates.iter().filter(|g| g.verdict == "BLOCKED").count();
    if blocked > 0 {
        return (
            "BLOCKED".to_string(),
            format!("{mode} verify: {blocked} gate(s) not completed (deadline exceeded)"),
        );
    }
    let failed: Vec<&Gate> = gates.iter().filter(|g| g.verdict == "FAIL").collect();
    let unknown = gates.iter().filter(|g| g.verdict == "UNKNOWN").count();
    if failed.is_empty() {
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
    }
}

fn execute_verify(
    repo: &Repo,
    config: &Config,
    mode: &str,
    timeouts: &VerifyTimeouts,
) -> VerifyRun {
    use std::time::Instant;
    let started_at = evidence::now_iso8601();
    let started = Instant::now();
    let global = if mode == "full" {
        GateBudget::from_limit(timeouts.full_deadline)
    } else {
        GateBudget::unlimited()
    };
    let deadline_ms = if mode == "full" {
        timeouts.full_deadline.map(|d| d.as_millis() as u64)
    } else {
        None
    };
    let deadline_secs = timeouts.full_deadline.map(|d| d.as_secs()).unwrap_or(0);
    // full 模式、门循环前预编一次场景实际引用的 example/bin；fast 不预编。
    let mut prebuild_ms = 0u64;
    let artifacts = if mode == "full" && !global.expired() {
        let all = crate::scenario::load_all(
            &config.scenarios_dir,
            &["product", "engineering", "platform", "regression"],
        );
        let built = crate::scenario::prebuild_scenario_artifacts(
            &all,
            repo,
            config.gate_budget("product-scenarios", global),
        );
        prebuild_ms = built.build_ms;
        Some(built)
    } else {
        None
    };
    let artifacts_ref = artifacts.as_ref();
    let names = gate_sequence(config, mode);
    let mut scenarios: Vec<ScenarioResult> = Vec::new();
    // 共享测试会话：门循环前构造一次，跨门存活（不写 evidence、不跨 run）。
    let mut shared_session = gates::SharedTestSession::new();

    let mut invoke = |name: &str, budget: GateBudget| -> Gate {
        gates::timed(|| match name {
            "whitespace" => gates::whitespace_gate(repo, budget),
            "format" => gates::format_gate(repo, budget),
            "check" => gates::check_gate(repo, budget),
            "clippy" => gates::clippy_gate(repo, budget),
            "architecture-delta" => gates::architecture_gate(config, budget),
            "dependency-delta" => gates::dependency_gate(repo, config, budget),
            "resource-type-neutrality" => gates::resource_kind_neutrality_gate(config, budget),
            "affected-tests" => gates::affected_tests_gate(repo, config, budget),
            "selected-properties" => gates::selected_properties_gate(repo, budget),
            "workspace-tests" => gates::shared_gate(
                &mut shared_session,
                gates::SharedGateKind::WorkspaceTests,
                repo,
                budget,
                global,
            ),
            "integration" => gates::shared_gate(
                &mut shared_session,
                gates::SharedGateKind::Integration,
                repo,
                budget,
                global,
            ),
            "product-scenarios" => scenario_gate_with_budget(
                config,
                name,
                &["product", "engineering", "platform"],
                artifacts_ref,
                budget,
                &timeouts.scenarios,
                &mut scenarios,
            ),
            "regression" => scenario_gate_with_budget(
                config,
                name,
                &["regression"],
                artifacts_ref,
                budget,
                &timeouts.scenarios,
                &mut scenarios,
            ),
            "architecture-policy" => gates::architecture_gate(config, budget),
            "dependency-governance" => gates::dependency_gate(repo, config, budget),
            "coverage-summary" => gates::coverage_gate(repo, budget),
            "selected-fuzz" => gates::fuzz_gate(repo, budget),
            "selected-concurrency" => gates::shared_gate(
                &mut shared_session,
                gates::SharedGateKind::SelectedConcurrency,
                repo,
                budget,
                global,
            ),
            "performance-budgets" => gates::performance_budgets_gate(config, budget),
            "bench" => gates::bench_gate(repo, config, budget),
            "platform-checks" => gates::platform_checks_gate(config, budget),
            "feature-matrix" => gates::feature_matrix_gate(repo, budget),
            "portable-core" => gates::portable_core_gate(repo, config, budget),
            other => gates::unimplemented(other),
        })
    };

    let (gates, deadline_exceeded) = run_gate_sequence(
        &names,
        global,
        deadline_secs,
        &|name, global| config.gate_budget(name, global),
        &mut invoke,
    );
    let timing = evidence::VerifyTiming {
        total_ms: started.elapsed().as_millis() as u64,
        started_at,
        deadline_ms,
        deadline_exceeded,
        prebuild_ms,
    };
    VerifyRun {
        gates,
        scenarios,
        timing,
    }
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
    let bindings = Bindings::current(&repo, &config);
    let run = execute_verify(&repo, &config, mode, &config.verify_timeouts);
    let (verdict, message) = aggregate_verdict(&run.gates, mode);

    let id = match evidence::write_evidence(
        &repo,
        &config,
        &verdict,
        &message,
        &run.gates,
        &run.scenarios,
        &bindings,
        &run.timing,
    ) {
        Ok(id) => id,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("evidence write failed: {e}"),
                vec![("gates".to_string(), gates_json(&run.gates))],
            );
        }
    };
    // 契约 §5.1 / evidence.schema.json：回读刚落盘的 evidence，核对 10 个
    // required 字段全部被真实填充。残缺即 BLOCKED（fail-closed）——宁堵一次
    // 验证，也不放行绑定不全的证据（STALE 判定依赖这些绑定字段）。
    if let Some(problem) = evidence_conformance(&config, &id) {
        return (
            "BLOCKED".to_string(),
            problem,
            vec![("gates".to_string(), gates_json(&run.gates))],
        );
    }

    let extras = vec![
        ("gates".to_string(), gates_json(&run.gates)),
        (
            "evidence".to_string(),
            json!({"id": id, "dir": format!("verify-{id}"), "verdict": verdict, "bindings": bindings.to_json()}),
        ),
    ];
    (verdict, message, extras)
}

fn scenario_run(
    config: &Config,
    gate_name: &str,
    subdirs: &[&str],
    artifacts: Option<&ScenarioArtifacts>,
    timeouts: &ScenarioTimeouts,
) -> (Vec<ScenarioResult>, Gate) {
    crate::scenario::run_gate(config, gate_name, subdirs, artifacts, timeouts)
}

/// 场景门级预算 fail-closed：`run_gate` 不含 budget（逐场景 tier 超时仍硬生效），
/// 调用后按墙钟判定；超过有效预算即覆写为 FAIL + `timed_out=true`（不中断
/// worker，但绝不静默 PASS）。
#[allow(clippy::too_many_arguments)]
fn scenario_gate_with_budget(
    config: &Config,
    gate_name: &str,
    subdirs: &[&str],
    artifacts: Option<&ScenarioArtifacts>,
    budget: GateBudget,
    timeouts: &ScenarioTimeouts,
    scenarios: &mut Vec<ScenarioResult>,
) -> Gate {
    let limit = budget.remaining();
    let started = std::time::Instant::now();
    let (results, mut gate) = scenario_run(config, gate_name, subdirs, artifacts, timeouts);
    scenarios.extend(results);
    if let Some(limit) = limit {
        if started.elapsed() > limit {
            gate = Gate::fail(
                gate_name,
                &format!("gate '{gate_name}' timed out after {}s", limit.as_secs()),
            );
            gate.timed_out = true;
        }
    }
    gate
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

// ---------------------------------------------------------------------------
// evidence 绑定契约（docs/e2e-test-system-contract.md §5.1）：
// engineering/evidence-schema/evidence.schema.json 的 10 个顶层 required
// 字段必须被真实填充，否则 STALE / status 等下游判定失去根基。
// ---------------------------------------------------------------------------

/// evidence.schema.json 顶层 10 个 required 字段的填充校验。
///
/// 实际落盘布局（evidence.rs）：`summary.json` 持 `schema_version` /
/// `verdict` / `id`（schema 的 `verification_id`）与 `bindings{...}`
/// （`source_revision` / `working_tree_digest` / `configuration_digest` /
/// `feature_set` / `target_triple` / `toolchain_version`）；`gates.json`
/// 持 `checks`（`gates` + `scenarios` 两个数组）。
///
/// 返回缺失/空/非法的字段清单（按 schema 字段名）；空 vec = 全部填充。
fn evidence_missing_required_fields(summary: &Value, checks: &Value) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    let non_empty_str =
        |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| !s.is_empty());

    if summary.get("schema_version").and_then(Value::as_i64) != Some(1) {
        missing.push("schema_version".to_string());
    }
    // verdict：存在、非空且属于 harness.toml [evidence].verdicts 枚举。
    match summary.get("verdict").and_then(Value::as_str) {
        Some("PASS" | "FAIL" | "STALE" | "UNKNOWN" | "BLOCKED") => {}
        _ => missing.push("verdict".to_string()),
    }
    if !non_empty_str(summary.get("id")) {
        missing.push("verification_id".to_string());
    }
    let bindings = summary.get("bindings");
    for field in [
        "source_revision",
        "working_tree_digest",
        "configuration_digest",
        "target_triple",
        "toolchain_version",
    ] {
        if !non_empty_str(bindings.and_then(|b| b.get(field))) {
            missing.push(field.to_string());
        }
    }
    let feature_set = bindings
        .and_then(|b| b.get("feature_set"))
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    if !feature_set {
        missing.push("feature_set".to_string());
    }
    // checks：verify 至少常驻 whitespace gate，故 gates 数组必非空。
    let has_checks = checks
        .get("gates")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    if !has_checks {
        missing.push("checks".to_string());
    }
    missing
}

/// 回读刚落盘的 evidence（`verify-<id>/summary.json` + `gates.json`）并核对
/// 契约 §5.1 的 required 字段。`Some(problem)` = 证据残缺（调用方 BLOCKED）。
fn evidence_conformance(config: &Config, id: &str) -> Option<String> {
    let dir = config.evidence_dir.join(format!("verify-{id}"));
    let read_json = |name: &str| -> Option<Value> {
        let text = std::fs::read_to_string(dir.join(name)).ok()?;
        serde_json::from_str::<Value>(&text).ok()
    };
    let (Some(summary), Some(checks)) = (read_json("summary.json"), read_json("gates.json")) else {
        return Some(format!(
            "evidence verify-{id} unreadable after write (summary.json / gates.json)"
        ));
    };
    let mut missing = evidence_missing_required_fields(&summary, &checks);
    missing.extend(evidence_timing_fields_missing(&summary, &checks));
    if missing.is_empty() {
        None
    } else {
        Some(format!(
            "evidence verify-{id} missing required fields (evidence.schema.json): {}",
            missing.join(", ")
        ))
    }
}

/// timing / duration_ms / timed_out / skipped_by_deadline 的字段级校验
/// （E2.4，缺失即 fail-closed）。
fn evidence_timing_fields_missing(summary: &Value, checks: &Value) -> Vec<String> {
    let mut missing = Vec::new();
    let Some(timing) = summary.get("timing") else {
        missing.push("timing".to_string());
        return missing;
    };
    if !timing.get("total_ms").is_some_and(Value::is_u64) {
        missing.push("timing.total_ms".to_string());
    }
    if !timing
        .get("started_at")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        missing.push("timing.started_at".to_string());
    }
    if !timing
        .get("deadline_exceeded")
        .is_some_and(Value::is_boolean)
    {
        missing.push("timing.deadline_exceeded".to_string());
    }
    if !timing.get("prebuild_ms").is_some_and(Value::is_u64) {
        missing.push("timing.prebuild_ms".to_string());
    }
    match timing.get("deadline_ms") {
        Some(Value::Null) => {}
        Some(v) if v.is_u64() => {}
        _ => missing.push("timing.deadline_ms".to_string()),
    }
    if let Some(gates) = checks.get("gates").and_then(Value::as_array) {
        for (i, gate) in gates.iter().enumerate() {
            if !gate.get("duration_ms").is_some_and(Value::is_u64) {
                missing.push(format!("gates[{i}].duration_ms"));
            }
            if !gate.get("timed_out").is_some_and(Value::is_boolean) {
                missing.push(format!("gates[{i}].timed_out"));
            }
            if !gate
                .get("skipped_by_deadline")
                .is_some_and(Value::is_boolean)
            {
                missing.push(format!("gates[{i}].skipped_by_deadline"));
            }
        }
    }
    if let Some(scenarios) = checks.get("scenarios").and_then(Value::as_array) {
        for (i, scenario) in scenarios.iter().enumerate() {
            if !scenario.get("duration_ms").is_some_and(Value::is_u64) {
                missing.push(format!("scenarios[{i}].duration_ms"));
            }
            if !scenario.get("timed_out").is_some_and(Value::is_boolean) {
                missing.push(format!("scenarios[{i}].timed_out"));
            }
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nexus-cmd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    /// 与 write_evidence 落盘形状一致的最小完整 evidence。
    fn complete_evidence() -> (Value, Value) {
        let summary = json!({
            "schema_version": 1,
            "command": "verify",
            "verdict": "PASS",
            "message": "fast verify: 8 gates, 8 pass, 0 fail, 0 unknown",
            "id": "abc123",
            "bindings": {
                "source_revision": "rev-1",
                "working_tree_digest": "wt-1",
                "dirty_state": false,
                "configuration_digest": "cfg-1",
                "feature_set": ["workspace:default"],
                "target_triple": "x86_64-pc-windows-msvc",
                "toolchain_version": "1.98.1",
                "harness_schema_version": 1,
                "platform_capability_digest": "p-1",
                "contract_hash": "c-1",
            },
            "timing": {
                "total_ms": 1000,
                "started_at": "2026-01-01T00:00:00.000Z",
                "deadline_ms": null,
                "deadline_exceeded": false,
                "prebuild_ms": 0,
            },
        });
        let checks = json!({
            "gates": [{
                "name": "whitespace",
                "verdict": "PASS",
                "detail": "ok",
                "duration_ms": 1,
                "timed_out": false,
                "skipped_by_deadline": false,
            }],
            "scenarios": []
        });
        (summary, checks)
    }

    #[test]
    fn evidence_missing_required_fields_accepts_complete_bindings() {
        let (summary, checks) = complete_evidence();
        assert!(evidence_missing_required_fields(&summary, &checks).is_empty());
    }

    /// 契约 §5.1：10 个 required 字段逐一被清空/破坏时，校验必须点名该字段。
    #[test]
    fn evidence_missing_required_fields_flags_each_required_field() {
        let (mut s, c) = complete_evidence();
        s["schema_version"] = json!(0);
        assert_eq!(
            evidence_missing_required_fields(&s, &c),
            vec!["schema_version"]
        );

        let (mut s, c) = complete_evidence();
        s["verdict"] = json!("MAYBE");
        assert_eq!(evidence_missing_required_fields(&s, &c), vec!["verdict"]);

        let (mut s, c) = complete_evidence();
        s["verdict"] = json!("");
        assert_eq!(evidence_missing_required_fields(&s, &c), vec!["verdict"]);

        let (mut s, c) = complete_evidence();
        s["id"] = json!("");
        assert_eq!(
            evidence_missing_required_fields(&s, &c),
            vec!["verification_id"]
        );

        for field in [
            "source_revision",
            "working_tree_digest",
            "configuration_digest",
            "target_triple",
            "toolchain_version",
        ] {
            let (mut s, c) = complete_evidence();
            s["bindings"][field] = json!("");
            assert_eq!(
                evidence_missing_required_fields(&s, &c),
                vec![field.to_string()],
                "empty bindings.{field} must be flagged"
            );
        }

        let (mut s, c) = complete_evidence();
        s["bindings"]["feature_set"] = json!([]);
        assert_eq!(
            evidence_missing_required_fields(&s, &c),
            vec!["feature_set"]
        );

        let (s, mut c) = complete_evidence();
        c["gates"] = json!([]);
        assert_eq!(evidence_missing_required_fields(&s, &c), vec!["checks"]);
    }

    /// 契约 §5.1 fail-closed：evidence 目录下 summary.json / gates.json 缺失
    /// （不可读）时 `evidence_conformance` 必须返回 Some——verify 据此 BLOCKED，
    /// 而不是放行一份绑定不全的证据（STALE 判定的根基）。
    #[test]
    fn evidence_conformance_blocks_unreadable_evidence() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let base = Config::load(&repo).expect("config must load");
        let tmp = temp_dir("evidence-unreadable");
        // evidence 目录故意不写任何文件。
        let config = Config {
            evidence_dir: tmp.join("evidence"),
            ..base
        };
        let problem = evidence_conformance(&config, "missing-id");
        assert!(
            problem.is_some(),
            "不可读 evidence 必须 fail-closed 返回 Some"
        );
        assert!(
            problem.unwrap().contains("unreadable"),
            "诊断必须点名 unreadable"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 契约 §5.1：verify 真实落盘的 evidence 必须填满 10 个 required 字段
    /// （用真实 repo + 临时 evidence 目录跑一次 write_evidence 后回读）。
    #[test]
    fn written_evidence_fills_all_schema_required_fields() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let base = Config::load(&repo).expect("config must load");
        let tmp = temp_dir("evidence-write");
        let config = Config {
            evidence_dir: tmp.join("evidence"),
            ..base
        };
        let bindings = Bindings::current(&repo, &config);
        let gates = vec![Gate::ok("whitespace", "no whitespace errors")];
        let timing = evidence::VerifyTiming {
            total_ms: 1,
            started_at: evidence::now_iso8601(),
            deadline_ms: None,
            deadline_exceeded: false,
            prebuild_ms: 0,
        };
        let id = evidence::write_evidence(
            &repo,
            &config,
            "PASS",
            "unit test",
            &gates,
            &[],
            &bindings,
            &timing,
        )
        .expect("write_evidence must succeed");
        assert!(
            evidence_conformance(&config, &id).is_none(),
            "written evidence must fill all schema-required fields"
        );
        // 回读的绑定必须与当前 repo 状态一致（STALE 判定的根基）。
        let text = std::fs::read_to_string(
            config
                .evidence_dir
                .join(format!("verify-{id}"))
                .join("summary.json"),
        )
        .expect("summary.json");
        let v: Value = serde_json::from_str(&text).expect("summary json");
        assert_eq!(v["bindings"]["source_revision"], json!(repo.revision()));
        assert_eq!(
            v["bindings"]["working_tree_digest"],
            json!(repo.working_tree_digest())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 契约 §5.1「契约哈希」的代码侧落地：`source_revision` 随提交变化、
    /// `working_tree_digest` 随工作区内容变化——evidence 绑定因此能识别
    /// "证据与当前 revision 不匹配"（STALE，契约 §4b）。
    #[test]
    fn evidence_bindings_track_source_and_worktree_changes() {
        let tmp = temp_dir("bindings-git");
        let repo = Repo { root: tmp.clone() };
        let commit = |msg: &str| {
            repo.git(&["add", "f.txt"]).expect("git add");
            repo.git(&[
                "-c",
                "user.name=harness-test",
                "-c",
                "user.email=harness-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                msg,
            ])
            .expect("git commit");
        };
        let config = Config {
            policies_dir: tmp.join("policies"),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.join("evidence"),
            crates_dir: tmp.join("crates"),
            engineering_dir: tmp.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        repo.git(&["init", "-q"]).expect("git init");
        std::fs::write(tmp.join("f.txt"), "one\n").expect("write");
        commit("one");

        let b1 = Bindings::current(&repo, &config);
        assert_eq!(b1.dirty_state, Some(false), "clean tree after commit");
        assert!(!b1.source_revision.is_empty());
        assert_ne!(b1.source_revision, "no-commit");
        assert!(!b1.working_tree_digest.is_empty());

        // 未提交的工作区变更：digest 变、revision 不变。
        std::fs::write(tmp.join("f.txt"), "two\n").expect("rewrite");
        let b2 = Bindings::current(&repo, &config);
        assert_eq!(b2.dirty_state, Some(true));
        assert_eq!(
            b1.source_revision, b2.source_revision,
            "uncommitted change must not move revision"
        );
        assert_ne!(
            b1.working_tree_digest, b2.working_tree_digest,
            "worktree digest must track content"
        );

        // 提交：revision 变（旧证据随之 STALE）。
        commit("two");
        let b3 = Bindings::current(&repo, &config);
        assert_eq!(b3.dirty_state, Some(false));
        assert_ne!(
            b2.source_revision, b3.source_revision,
            "commit must move revision"
        );
        assert_ne!(
            b1.working_tree_digest, b3.working_tree_digest,
            "committed content must move tree digest"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 契约 §4.4 的镜像守卫：quality.toml 声明的每个 gate 都必须在 verify()
    /// 的 match 里有确定路由。新增声明忘记路由时此处 FAIL（而不是运行时落
    /// `unimplemented()` 兜底记 UNKNOWN）。
    #[test]
    fn every_declared_gate_is_routed_in_verify() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let config = Config::load(&repo).expect("config must load");
        const ROUTED: &[&str] = &[
            // fast
            "format",
            "check",
            "clippy",
            "architecture-delta",
            "dependency-delta",
            "resource-type-neutrality",
            "affected-tests",
            "selected-properties",
            // full
            "workspace-tests",
            "integration",
            "product-scenarios",
            "regression",
            "architecture-policy",
            "dependency-governance",
            "coverage-summary",
            "selected-fuzz",
            "selected-concurrency",
            "performance-budgets",
            "bench",
            "platform-checks",
            "feature-matrix",
            "portable-core",
        ];
        for level in ["fast", "full"] {
            for name in config.declared_gates(level) {
                assert!(
                    ROUTED.contains(&name.as_str()),
                    "gate '{name}' declared in policies/quality.toml [{level}] but not routed in verify() — add a deterministic implementation in gates.rs or record the specific UNKNOWN reason"
                );
            }
        }
    }

    fn seq_timeouts() -> VerifyTimeouts {
        VerifyTimeouts::defaults()
    }

    #[test]
    fn run_gate_sequence_timeout_continues() {
        let names = vec!["a".to_string(), "b".to_string()];
        let timeouts = seq_timeouts();
        let mut calls = 0usize;
        let (gates, deadline_exceeded) = run_gate_sequence(
            &names,
            GateBudget::unlimited(),
            3600,
            &|name, global| crate::config::gate_budget_for(&timeouts, name, global),
            &mut |name: &str, _budget: GateBudget| -> Gate {
                calls += 1;
                if name == "a" {
                    let mut g = Gate::fail(name, "gate 'a' timed out after 1s");
                    g.timed_out = true;
                    g
                } else {
                    Gate::ok(name, "ok")
                }
            },
        );
        assert_eq!(calls, 2, "timeout must not stop later gates");
        assert!(!deadline_exceeded);
        assert_eq!(gates[0].verdict, "FAIL");
        assert!(gates[0].timed_out);
        assert!(!gates[0].skipped_by_deadline);
        assert_eq!(gates[1].verdict, "PASS");
        assert_eq!(aggregate_verdict(&gates, "full").0, "FAIL");
    }

    #[test]
    fn run_gate_sequence_deadline_blocks_remaining() {
        let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let timeouts = seq_timeouts();
        let global = GateBudget::from_limit(Some(std::time::Duration::from_millis(1)));
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut calls = 0usize;
        let (gates, deadline_exceeded) = run_gate_sequence(
            &names,
            global,
            3600,
            &|name, global| crate::config::gate_budget_for(&timeouts, name, global),
            &mut |name: &str, _budget: GateBudget| -> Gate {
                calls += 1;
                Gate::ok(name, "should not run")
            },
        );
        assert_eq!(calls, 0, "no gate may run after the deadline");
        assert!(deadline_exceeded);
        assert_eq!(gates.len(), 3);
        for gate in &gates {
            assert_eq!(gate.verdict, "BLOCKED");
            assert!(gate.skipped_by_deadline);
            assert!(!gate.timed_out);
            assert_eq!(gate.duration_ms, 0);
            assert!(gate.detail.contains("not run"), "{}", gate.detail);
        }
        assert_eq!(aggregate_verdict(&gates, "full").0, "BLOCKED");
    }

    #[test]
    fn run_gate_sequence_interrupts_current_gate() {
        let names = vec!["a".to_string(), "b".to_string()];
        let timeouts = seq_timeouts();
        let global = GateBudget::from_limit(Some(std::time::Duration::from_millis(300)));
        let (gates, deadline_exceeded) = run_gate_sequence(
            &names,
            global,
            3600,
            &|name, global| crate::config::gate_budget_for(&timeouts, name, global),
            &mut |name: &str, _budget: GateBudget| -> Gate {
                std::thread::sleep(std::time::Duration::from_millis(400));
                let mut g = Gate::fail(name, "gate 'a' timed out after 0s");
                g.timed_out = true;
                g.duration_ms = 400;
                g
            },
        );
        assert!(deadline_exceeded);
        assert_eq!(gates.len(), 2);
        assert_eq!(gates[0].verdict, "BLOCKED");
        assert!(gates[0].skipped_by_deadline);
        assert!(!gates[0].timed_out);
        assert!(gates[0].duration_ms > 0);
        assert_eq!(gates[1].verdict, "BLOCKED");
        assert!(gates[1].skipped_by_deadline);
    }

    #[test]
    fn aggregate_prefers_blocked_over_fail() {
        let blocked = Gate::blocked("a", "not run");
        let fail = Gate::fail("b", "boom");
        let pass = Gate::ok("c", "ok");
        let unknown = Gate::unknown("d", "unknown");
        assert_eq!(
            aggregate_verdict(&[blocked.clone(), fail.clone()], "full").0,
            "BLOCKED"
        );
        assert_eq!(aggregate_verdict(&[fail, pass.clone()], "full").0, "FAIL");
        assert_eq!(
            aggregate_verdict(&[pass, unknown], "full").0,
            "PASS",
            "UNKNOWN must not block (existing semantics)"
        );
    }

    #[test]
    fn evidence_conformance_rejects_missing_timing() {
        let (summary, checks) = complete_evidence();
        assert!(evidence_timing_fields_missing(&summary, &checks).is_empty());

        let mut no_timing = summary.clone();
        no_timing.as_object_mut().unwrap().remove("timing");
        assert_eq!(
            evidence_timing_fields_missing(&no_timing, &checks),
            vec!["timing".to_string()]
        );

        for (pointer, expected) in [
            ("/timing/total_ms", "timing.total_ms"),
            ("/timing/started_at", "timing.started_at"),
            ("/timing/deadline_exceeded", "timing.deadline_exceeded"),
            ("/timing/prebuild_ms", "timing.prebuild_ms"),
        ] {
            let mut broken = summary.clone();
            if let Some(obj) = broken.pointer_mut(pointer) {
                *obj = Value::Null;
            }
            assert!(
                evidence_timing_fields_missing(&broken, &checks)
                    .iter()
                    .any(|m| m == expected),
                "{pointer} removal must be flagged"
            );
        }

        let mut no_gate_duration = checks.clone();
        no_gate_duration["gates"][0]
            .as_object_mut()
            .unwrap()
            .remove("duration_ms");
        assert!(
            evidence_timing_fields_missing(&summary, &no_gate_duration)
                .iter()
                .any(|m| m == "gates[0].duration_ms")
        );

        let tmp = temp_dir("conf-timing");
        let config = Config {
            policies_dir: tmp.clone(),
            scenarios_dir: tmp.clone(),
            evidence_dir: tmp.clone(),
            crates_dir: tmp.clone(),
            engineering_dir: tmp.clone(),
            quality: json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: VerifyTimeouts::defaults(),
        };
        let id = "abc123";
        let dir = tmp.join(format!("verify-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("summary.json"),
            serde_json::to_string(&no_timing).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("gates.json"),
            serde_json::to_string(&checks).unwrap(),
        )
        .unwrap();
        let problem = evidence_conformance(&config, id).expect("must be blocked");
        assert!(problem.contains("timing"), "{problem}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
