//! `nexus-harness scenario <list|run>`：场景包机器接口（Track A）。
//!
//! 把 `scenarios/` 下的产品/回归场景变成 agent 可直接调用的固定程序：
//! agent 不再手写检查脚本，只调用固定命令、读机器可读结果。
//!
//! 机器接口（CONTRACT-scenario-pack.md 冻结，字段名不可更改）：
//! - `scenario list --json` → {"schema_version":1,"scenarios":[{"name","subdir","summary","requires"}]}
//! - `scenario run <name> --json` → {"schema_version":1,"command":"scenario run",
//!   "scenario","verdict":"PASS|FAIL|BLOCKED","evidence_id",
//!   "failure_signature":{"failed_step","assertion","key_log_lines":[]},"duration_ms"}
//!
//! 注意：main.rs 的顶层 envelope 先写 `"command": "<首 token>"`（即 "scenario"），
//! 本模块在 extras 里覆盖为更精确的 "scenario list" / "scenario run"
//!（extras 在 envelope 字段之后插入，键冲突时覆盖）。

use crate::commands;
use crate::config::Config;
use crate::env::Repo;
use crate::evidence::{self, Bindings};
use crate::evidence_index;
use crate::scenario;
use serde_json::{Value, json};

type Outcome = (String, String, Vec<(String, Value)>);

/// 子目录扫描顺序：与 verify --full 的 product-scenarios 门禁一致，另加 regression。
const SCAN_SUBDIRS: &[&str] = &["product", "regression", "platform", "engineering"];

pub fn dispatch(args: &[String]) -> Outcome {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "list" => list(),
        "run" => run_one(args.get(1).map(String::as_str).unwrap_or("")),
        "index" => index(&args[1..]),
        _ => (
            "BLOCKED".to_string(),
            "usage: nexus-harness scenario <list|run|index> [--json]; run needs a scenario id; \
             index needs --write or --check"
                .to_string(),
            vec![("command".to_string(), json!("scenario"))],
        ),
    }
}

fn list() -> Outcome {
    let (_repo, config) = match commands::setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let (scenarios, load_errors) =
        scenario::load_all_reporting(&config.scenarios_dir, SCAN_SUBDIRS);
    if !load_errors.is_empty() {
        // fail-closed：加载失败不能退化成「少几个场景的 PASS 列表」。
        return (
            "BLOCKED".to_string(),
            format!(
                "{} scenario file(s) failed to load:\n{}",
                load_errors.len(),
                load_errors.join("\n")
            ),
            vec![
                ("command".to_string(), json!("scenario list")),
                ("scenarios".to_string(), json!([])),
            ],
        );
    }
    let arr: Vec<Value> = scenarios
        .iter()
        .map(|s| {
            json!({
                "name": s.id,
                "subdir": s.subdir,
                "summary": s.title,
                "requires": scenario::scenario_requires(s),
                "carrier": s.carrier.as_str(),
            })
        })
        .collect();
    (
        "PASS".to_string(),
        format!("{} scenario(s)", arr.len()),
        vec![
            ("command".to_string(), json!("scenario list")),
            ("scenarios".to_string(), json!(arr)),
        ],
    )
}

/// `scenario index --write|--check`：仓库内证据索引（P4）。
///
/// 与 `architecture_gate` 共用 `evidence_index::check`，单一实现。
fn index(args: &[String]) -> Outcome {
    let (repo, config) = match commands::setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let want_write = args.iter().any(|a| a == "--write");
    let want_check = args.iter().any(|a| a == "--check");
    if want_write == want_check {
        return (
            "BLOCKED".to_string(),
            "usage: nexus-harness scenario index <--write|--check> [--json]".to_string(),
            vec![("command".to_string(), json!("scenario index"))],
        );
    }
    if want_write {
        write_index(&repo, &config)
    } else {
        check_index(&repo, &config)
    }
}

fn index_outcome(verdict: &str, message: String, detail: String) -> Outcome {
    (
        verdict.to_string(),
        message,
        vec![
            ("command".to_string(), json!("scenario index")),
            ("path".to_string(), json!(evidence_index::INDEX_PATH)),
            ("detail".to_string(), json!(detail)),
        ],
    )
}

fn write_index(repo: &Repo, config: &Config) -> Outcome {
    let mut rows = match evidence_index::collect(config) {
        Ok(rows) => rows,
        Err(errors) => {
            return index_outcome(
                "FAIL",
                format!("{} scenario/index error(s)", errors.len()),
                errors.join("\n"),
            );
        }
    };
    let path = repo.root.join(evidence_index::INDEX_PATH);
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => match evidence_index::parse(&text) {
            Ok(rows) => Some(rows),
            Err(errors) => {
                return index_outcome(
                    "FAIL",
                    "existing index is malformed".to_string(),
                    errors.join("\n"),
                );
            }
        },
        Err(_) => None,
    };
    // Q3：id 已存在且 carrier 未变 → 保留既有 first_revision（列名是「首次记录」，
    // 每次刷新会让列名说谎并产生 338 行噪声）。
    if let Some(existing) = existing {
        for row in &mut rows {
            if let Some(prev) = existing
                .iter()
                .find(|p| p.id == row.id && p.carrier == row.carrier)
            {
                row.first_revision = prev.first_revision.clone();
            }
        }
    }
    let latest = evidence_index::latest_revision(config);
    let text = evidence_index::render(&rows, latest.as_deref());
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return index_outcome("FAIL", format!("mkdir failed: {e}"), String::new());
        }
    }
    if let Err(e) = std::fs::write(&path, &text) {
        return index_outcome("FAIL", format!("write failed: {e}"), String::new());
    }
    // 写盘后自跑 check（自证一致，不通过即报错）。
    match evidence_index::check(repo, config) {
        Ok(detail) => index_outcome(
            "PASS",
            format!(
                "wrote {} rows (revision seed: {})",
                rows.len(),
                latest.as_deref().unwrap_or("unrecorded")
            ),
            detail,
        ),
        Err(errors) => index_outcome(
            "FAIL",
            "index written but self-check failed".to_string(),
            errors.join("\n"),
        ),
    }
}

fn check_index(repo: &Repo, config: &Config) -> Outcome {
    match evidence_index::check(repo, config) {
        Ok(detail) => index_outcome("PASS", detail.clone(), detail),
        Err(errors) => index_outcome(
            "FAIL",
            format!("{} index mismatch(es)", errors.len()),
            errors.join("\n"),
        ),
    }
}

fn run_one(name: &str) -> Outcome {
    if name.is_empty() {
        return (
            "BLOCKED".to_string(),
            "usage: nexus-harness scenario run <scenario-id> [--json]".to_string(),
            vec![
                ("command".to_string(), json!("scenario run")),
                ("scenario".to_string(), json!("")),
                ("evidence_id".to_string(), Value::Null),
                (
                    "failure_signature".to_string(),
                    json!({"failed_step": "lookup", "assertion": "", "key_log_lines": []}),
                ),
                ("duration_ms".to_string(), json!(0)),
            ],
        );
    }
    let (repo, config) = match commands::setup() {
        Ok(x) => x,
        Err(o) => return o,
    };
    let scenarios = scenario::load_all(&config.scenarios_dir, SCAN_SUBDIRS);
    let Some(target) = scenarios.iter().find(|s| s.id == name) else {
        return blocked_unknown(
            &repo,
            &config,
            name,
            "lookup",
            String::new(),
            format!("unknown scenario id: {name}"),
        );
    };
    let rep = scenario::run_single(target, None, &crate::config::ScenarioTimeouts::legacy());
    // 机器接口只允许 PASS | FAIL | BLOCKED：UNKNOWN（平台不匹配/静态契约/
    // n3 contract-first 未实现）映射为 BLOCKED。
    let verdict = match rep.verdict.as_str() {
        "PASS" => "PASS",
        "FAIL" => "FAIL",
        _ => "BLOCKED",
    };
    let failure_signature = json!({
        "failed_step": rep.failed_step,
        "assertion": rep.assertion,
        "key_log_lines": rep.key_log_lines,
    });
    let bindings = Bindings::current(&repo, &config);
    let message = format!("scenario {name}: {} ({})", verdict, rep.detail);
    let ev = evidence::ScenarioEvidence {
        scenario_id: name,
        verdict,
        message: &message,
        failure_signature: &failure_signature,
        duration_ms: rep.duration_ms,
        output: rep.output.as_ref(),
    };
    match evidence::write_scenario_evidence(&repo, &config, &ev, &bindings) {
        Ok(id) => (
            verdict.to_string(),
            message,
            vec![
                ("command".to_string(), json!("scenario run")),
                ("scenario".to_string(), json!(name)),
                ("evidence_id".to_string(), json!(id)),
                ("failure_signature".to_string(), failure_signature),
                ("duration_ms".to_string(), json!(rep.duration_ms)),
            ],
        ),
        Err(e) => (
            "BLOCKED".to_string(),
            format!("evidence write failed: {e}"),
            vec![
                ("command".to_string(), json!("scenario run")),
                ("scenario".to_string(), json!(name)),
                ("evidence_id".to_string(), Value::Null),
                ("failure_signature".to_string(), failure_signature),
                ("duration_ms".to_string(), json!(rep.duration_ms)),
            ],
        ),
    }
}

/// lookup 失败（场景 id 不存在）：写一份 BLOCKED 证据再返回。
fn blocked_unknown(
    repo: &crate::env::Repo,
    config: &crate::config::Config,
    name: &str,
    failed_step: &str,
    assertion: String,
    message: String,
) -> Outcome {
    let failure_signature = json!({
        "failed_step": failed_step,
        "assertion": assertion,
        "key_log_lines": [],
    });
    let bindings = Bindings::current(repo, config);
    let ev = evidence::ScenarioEvidence {
        scenario_id: name,
        verdict: "BLOCKED",
        message: &message,
        failure_signature: &failure_signature,
        duration_ms: 0,
        output: None,
    };
    let evidence_id = evidence::write_scenario_evidence(repo, config, &ev, &bindings).ok();
    (
        "BLOCKED".to_string(),
        message,
        vec![
            ("command".to_string(), json!("scenario run")),
            ("scenario".to_string(), json!(name)),
            (
                "evidence_id".to_string(),
                evidence_id.map(Value::String).unwrap_or(Value::Null),
            ),
            ("failure_signature".to_string(), failure_signature),
            ("duration_ms".to_string(), json!(0)),
        ],
    )
}
