//! Evidence store: write/read .evidence/verify-<id>/, freshness binding,
//! STALE marking (surfaced to .githooks/pre-push).

use crate::config::Config;
use crate::env::Repo;
use crate::gates::Gate;
use crate::scenario::{Carrier, ScenarioResult};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

pub struct Bindings {
    pub source_revision: String,
    pub working_tree_digest: String,
    /// `None` = git 状态查询失败，此时**不产出**"干净/不干净"这一事实（序列化为 null）。
    pub dirty_state: Option<bool>,
    pub configuration_digest: String,
    pub feature_set: Vec<String>,
    pub target_triple: String,
    pub toolchain_version: String,
    pub harness_schema_version: u32,
    pub platform_capability_digest: String,
    pub contract_hash: String,
}

impl Bindings {
    pub fn current(repo: &Repo, config: &Config) -> Bindings {
        let (toolchain, target) = crate::env::toolchain();
        // harness.toml [evidence].bind_working_tree_digest 兑现点：
        // false → 记录哨兵值 "unbound"（status/explain JSON 可见，且 id
        // seed 里该分量退化为常量）；true → 内容绑定 digest。
        let working_tree_digest = if config.bind_working_tree_digest {
            repo.working_tree_digest()
        } else {
            "unbound".to_string()
        };
        Bindings {
            source_revision: repo.revision(),
            working_tree_digest,
            dirty_state: repo.dirty_state(),
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

/// verify-<id> short id: first 12 chars of
/// hash(revision|configuration|contract[|working_tree_digest when dirty]),
/// namespaced by the current agent (env `NEXUS_AGENT`) so multiple agents
/// working on the same revision do not overwrite each other's evidence.
///
/// digest 进 seed 的条件是 `dirty_state != Some(false)`：脏树**和**"git 问不出
/// 脏净"两种情况都进（后者带的是 `dirty-unknown` 哨兵 digest，因此既不会折叠成
/// 干净树的 id，也不会与任何真实内容 id 相同）。刻意**不在干净树上加入**：
/// CI/干净树的 id 因此与旧实现逐字节一致，既有 `verify-<id>` 引用、
/// `nexus-sync.sh`（fetch→rebase→verify→push）流程与可复现性全部不受影响；
/// 脏树则"每份内容一个 id"，内容漂移自然产生新目录，旧证据被
/// `mark_stale_others` 标 STALE，而不是被同 id 的 `fs::write` 静默覆写
/// （缺陷 EXP4 的直接成因）。
///
/// **为什么 id 里没有墙钟时间戳**：`.evidence/` 目录是入库对象，AGENTS.md
/// 与技能文档以 `verify-<id>` 作为可追溯标识引用；时间戳进 seed 会让每次
/// run 都产生新目录、文档引用当场失效、跨机复现不可能。取证需求的运行
/// 时刻属于 summary/metadata 字段，不属于身份。
pub fn verify_id(repo: &Repo, b: &Bindings) -> String {
    let mut seed = format!(
        "{}\n{}\n{}",
        b.source_revision, b.configuration_digest, b.contract_hash
    );
    if b.dirty_state != Some(false) {
        seed.push('\n');
        seed.push_str(&b.working_tree_digest);
    }
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

/// days-since-epoch → (year, month, day)（Howard Hinnant civil_from_days，
/// 无新依赖；见 https://howardhinnant.github.io/date_algorithms.html）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// UTC 墙钟 ISO-8601（毫秒精度）。运行时刻写进 summary 供取证——它是
/// 字段而不是 id 分量（见 `verify_id` 文档注释对时间戳为何不入 id 的说明）。
pub(crate) fn now_iso8601() -> String {
    created_at_iso8601()
}

fn created_at_iso8601() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, mo, dd) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{dd:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Read a verify dir's summary.json if present and parsable.
fn read_summary(dir: &std::path::Path) -> Option<Value> {
    let text = fs::read_to_string(dir.join("summary.json")).ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

/// 同 id 覆写保护：`verify-<id>` 目录已存在、且其中记录的 bindings 与本次
/// 不同（id seed 只含 revision/configuration/contract[+脏树 digest]，
/// toolchain、target 等分量变化仍可能撞进同一 id）时，**不静默覆写**：
/// 把旧证据整体移入兄弟目录 `verify-<id>-stale-<hash>` 并把其 summary
/// 标为 STALE 后保留（删除证据属人工决定，harness 无权销毁历史），再让
/// 本次 run 写入正主目录。
/// bindings 完全相同 → 幂等刷新（同一精确状态的重跑，覆写无害，允许）。
/// summary.json 缺失/不可解析（崩溃残留的半成品）→ 直接覆写修复。
fn preserve_stale_if_bindings_differ(
    repo: &Repo,
    dir: &std::path::Path,
    current_bindings: &Value,
) -> Result<(), String> {
    if !dir.is_dir() {
        return Ok(());
    }
    let Some(mut old) = read_summary(dir) else {
        return Ok(());
    };
    let previous = old.get("bindings").cloned().unwrap_or(Value::Null);
    if previous == *current_bindings {
        return Ok(());
    }
    let h = repo
        .hash_stdin(&previous.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let short = if h.len() > 12 { &h[..12] } else { h.as_str() };
    let base = PathBuf::from(format!("{}-stale-{short}", dir.to_string_lossy()));
    let mut target = base.clone();
    let mut n: u32 = 1;
    while target.is_dir() {
        target = PathBuf::from(format!("{}-{n}", base.display()));
        n += 1;
    }
    fs::rename(dir, &target).map_err(|e| format!("preserve {}: {e}", dir.display()))?;
    old["verdict"] = json!("STALE");
    old["message"] = json!(
        "same evidence id produced with different bindings; preserved here by the newer run instead of being silently overwritten"
    );
    write_json(&target.join("summary.json"), &old)
}

/// 一次 verify 的计时快照（evidence `summary.timing`）。
///
/// 门级 `duration_ms` 不可直接累加求和；整轮总耗时只认 `total_ms`。
pub struct VerifyTiming {
    pub total_ms: u64,
    pub started_at: String,
    pub deadline_ms: Option<u64>,
    pub deadline_exceeded: bool,
    pub prebuild_ms: u64,
}

/// Write full evidence for a verify run; marks prior evidence with differing
/// bindings as STALE; refreshes .evidence/latest.json.
#[allow(clippy::too_many_arguments)]
pub fn write_evidence(
    repo: &Repo,
    config: &Config,
    verdict: &str,
    message: &str,
    gates: &[Gate],
    scenarios: &[ScenarioResult],
    bindings: &Bindings,
    timing: &VerifyTiming,
) -> Result<String, String> {
    let id = verify_id(repo, bindings);
    let dir = config.evidence_dir.join(format!("verify-{id}"));
    let bindings_json = bindings.to_json();
    preserve_stale_if_bindings_differ(repo, &dir, &bindings_json)?;
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;

    let summary = {
        let mut summary = json!({
            "schema_version": 1,
            "command": "verify",
            "verdict": verdict,
            "message": message,
            "id": id,
            "created_at": created_at_iso8601(),
            "bindings": bindings_json,
            "timing": {
                "total_ms": timing.total_ms,
                "started_at": timing.started_at,
                "deadline_ms": timing.deadline_ms,
                "deadline_exceeded": timing.deadline_exceeded,
                "prebuild_ms": timing.prebuild_ms,
            },
        });
        // carrier 统计只在真的有场景结果时写出：fast 无场景执行时 0/0/0
        // 会被误读成「全覆盖」，故缺省不写该块。
        if !scenarios.is_empty() {
            let mut counts: std::collections::BTreeMap<Carrier, usize> =
                Carrier::ALL.into_iter().map(|c| (c, 0)).collect();
            for s in scenarios {
                *counts.entry(s.carrier).or_insert(0) += 1;
            }
            let carriers = counts
                .iter()
                .map(|(c, n)| (c.as_str().to_string(), json!(n)))
                .collect::<serde_json::Map<String, Value>>();
            let total = scenarios.len();
            // ScenarioResult.carrier 非 Option ⇒ 全部已声明；missing 恒为 0，
            // 但仍按声明/缺失计数字段输出，供 AC-14 机读。
            let declared = total;
            summary["carriers"] = Value::Object(carriers);
            summary["carrier_coverage"] = json!({
                "scenarios_total": total,
                "declared": declared,
                "missing": total - declared,
            });
        }
        summary
    };
    let gates_json: Vec<Value> = gates
        .iter()
        .map(|g| {
            json!({
                "name": g.name,
                "verdict": g.verdict,
                "detail": g.detail,
                "duration_ms": g.duration_ms,
                "timed_out": g.timed_out,
                "skipped_by_deadline": g.skipped_by_deadline,
            })
        })
        .collect();
    let scenarios_json: Vec<Value> = scenarios
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "carrier": s.carrier.as_str(),
                "verdict": s.verdict,
                "detail": s.detail,
                "duration_ms": s.duration_ms,
                "timed_out": s.timed_out,
            })
        })
        .collect();
    let checks = json!({"gates": gates_json, "scenarios": scenarios_json});

    write_json(&dir.join("summary.json"), &summary)?;
    write_json(&dir.join("gates.json"), &checks)?;
    write_json(
        &dir.join("metadata.json"),
        &json!({"bindings": bindings_json, "env": {
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
    pub output: Option<&'a Value>,
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

    let mut summary = json!({
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
    if let Some(output) = ev.output {
        summary["output"] = output.clone();
    }
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
            dirty_state: Some(false),
            configuration_digest: "cfg".to_string(),
            feature_set: vec!["f".to_string()],
            target_triple: "t".to_string(),
            toolchain_version: "1.0".to_string(),
            harness_schema_version: 1,
            platform_capability_digest: "p".to_string(),
            contract_hash: "c".to_string(),
        }
    }

    /// `Config` for tests that need `Bindings::current` (which reads the
    /// `[evidence].bind_working_tree_digest` flag). All directories point under
    /// `dir`; bind defaults to `true` so the sentinel/unknown paths stay reachable.
    fn test_timing() -> VerifyTiming {
        VerifyTiming {
            total_ms: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            deadline_ms: None,
            deadline_exceeded: false,
            prebuild_ms: 0,
        }
    }

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            policies_dir: dir.join("policies"),
            scenarios_dir: dir.join("scenarios"),
            evidence_dir: dir.to_path_buf(),
            crates_dir: dir.join("crates"),
            engineering_dir: dir.join("engineering"),
            quality: json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
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
    fn dirty_state_none_serializes_as_null_not_false() {
        // 独立 Review round 3 待办 2：`dirty_state` 的 `None` 分支此前零测试。
        // "git 问不出干净与否"绝不能被写成"干净"——那是往 Evidence 里伪造事实。
        let mut b = bindings("r1");
        b.dirty_state = None;
        let json = b.to_json();
        assert!(
            json["dirty_state"].is_null(),
            "None 必须是 null，实际：{}",
            json["dirty_state"]
        );
        assert_ne!(
            json,
            bindings("r1").to_json(),
            "null 与 false 不得是同一个绑定"
        );
    }

    #[test]
    fn bindings_from_non_repo_root_keep_dirty_state_unknown() {
        // 结构性覆盖：真正的 git 失败路径（root 不是仓库）下 `Bindings::current`
        // 产出 `None`，而不是 `Some(false)`。
        let root = std::env::temp_dir().join(format!("nexus-ev-not-a-repo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let repo = Repo { root: root.clone() };
        assert!(
            repo.git(&["rev-parse", "--show-toplevel"]).is_err(),
            "本测试需要一个不在任何 git 仓库内的临时目录"
        );
        let b = Bindings::current(&repo, &test_config(&root));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(b.dirty_state, None, "git 失败时不得产出脏/净判断");
        assert!(
            b.working_tree_digest.contains("unknown"),
            "同一失败下工作树指纹也必须带哨兵值：{}",
            b.working_tree_digest
        );
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
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
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
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
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

    #[test]
    fn verify_id_binds_digest_only_when_dirty() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        // 脏树：仅 digest 不同 → id 必须不同（旧实现同 id → 静默覆写的根因）。
        let mut a = bindings("r1");
        a.dirty_state = Some(true);
        a.working_tree_digest = "digest-A".to_string();
        let mut b = bindings("r1");
        b.dirty_state = Some(true);
        b.working_tree_digest = "digest-B".to_string();
        assert_ne!(verify_id(&repo, &a), verify_id(&repo, &b));
        // 干净树：digest 不进 seed → 与旧实现逐字节一致（向后兼容）。
        let mut c = bindings("r1");
        c.dirty_state = Some(false);
        c.working_tree_digest = "digest-A".to_string();
        let mut d = bindings("r1");
        d.dirty_state = Some(false);
        d.working_tree_digest = "digest-B".to_string();
        assert_eq!(verify_id(&repo, &c), verify_id(&repo, &d));
        // 旧 seed 手算比对：hash(revision|configuration|contract) 前 12 hex。
        let legacy = repo.hash_stdin("r1\ncfg\nc").unwrap();
        let expected = format_verify_id(agent_tag().as_deref(), &legacy[..12]);
        assert_eq!(verify_id(&repo, &c), expected);
    }

    #[test]
    fn verify_id_keeps_unknown_dirty_state_distinct_from_clean() {
        // #12 把 dirty_state 变成 Option<bool>；`None` = git 问不出脏净。
        // 此时 digest 是哨兵值，必须进 seed：否则一次 git 失败会拿到与"干净树
        // run"完全相同的 id，把"不知道"折叠成"干净"——正是本轮收口的 fail-open 形态。
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let mut clean = bindings("r1");
        clean.dirty_state = Some(false);
        clean.working_tree_digest = "dirty-unknown".to_string();
        let mut unknown = bindings("r1");
        unknown.dirty_state = None;
        unknown.working_tree_digest = "dirty-unknown".to_string();
        assert_ne!(
            verify_id(&repo, &unknown),
            verify_id(&repo, &clean),
            "None 不得与 Some(false) 同 id"
        );
        // 同一个 None 状态仍然确定：id 里不掺墙钟、不掺随机。
        let mut unknown2 = bindings("r1");
        unknown2.dirty_state = None;
        unknown2.working_tree_digest = "dirty-unknown".to_string();
        assert_eq!(verify_id(&repo, &unknown), verify_id(&repo, &unknown2));
        // 哨兵 digest 与真实内容 digest 也不同 id（未知 ≠ 任一已知内容）。
        let mut dirty = bindings("r1");
        dirty.dirty_state = Some(true);
        dirty.working_tree_digest = "real-content-digest".to_string();
        assert_ne!(verify_id(&repo, &unknown), verify_id(&repo, &dirty));
    }

    #[test]
    fn same_id_different_bindings_not_silently_overwritten() {
        // 缺陷 EXP4 的守门测试：id 相同但 bindings 不同（如 toolchain 变化）
        // 时，旧证据必须被保留并标 STALE，而不是被 fs::write 原地抹掉；
        // bindings 完全相同则幂等刷新、不产生额外目录。
        let repo = crate::env::tests::init_temp_repo("ovr");
        let ev_dir = repo.root.join("evidence");
        std::fs::create_dir_all(&ev_dir).unwrap();
        let config = Config {
            policies_dir: ev_dir.join("policies"),
            scenarios_dir: ev_dir.join("scenarios"),
            evidence_dir: ev_dir.clone(),
            crates_dir: ev_dir.join("crates"),
            engineering_dir: ev_dir.join("engineering"),
            quality: json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        let mut b1 = bindings("rev-same");
        b1.toolchain_version = "1.0.0".to_string();
        let mut b2 = bindings("rev-same");
        b2.toolchain_version = "1.1.0".to_string();
        // toolchain 不在 id seed 里 → 同 id、不同 bindings。
        let id = verify_id(&repo, &b1);
        assert_eq!(id, verify_id(&repo, &b2));

        write_evidence(
            &repo,
            &config,
            "PASS",
            "run-1",
            &[],
            &[],
            &b1,
            &test_timing(),
        )
        .unwrap();
        write_evidence(
            &repo,
            &config,
            "PASS",
            "run-2",
            &[],
            &[],
            &b2,
            &test_timing(),
        )
        .unwrap();

        // 正主目录是 run-2 的新 bindings。
        let cur: Value = serde_json::from_str(
            &std::fs::read_to_string(ev_dir.join(format!("verify-{id}/summary.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(cur["bindings"], b2.to_json());
        assert_eq!(cur["verdict"], json!("PASS"));
        // run-1 被保留为 STALE 兄弟目录，bindings 仍是旧的。
        let preserved = std::fs::read_dir(&ev_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("verify-{id}-stale-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(preserved.len(), 1, "old evidence must survive exactly once");
        let old: Value = serde_json::from_str(
            &std::fs::read_to_string(preserved[0].path().join("summary.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(old["verdict"], json!("STALE"));
        assert_eq!(old["bindings"], b1.to_json());
        assert!(
            std::fs::read(preserved[0].path().join("gates.json")).is_ok(),
            "preserved dir keeps its full evidence files"
        );

        // 幂等刷新：同 bindings 再跑一次 → 不新增 stale 目录，正主目录更新。
        write_evidence(
            &repo,
            &config,
            "PASS",
            "run-3",
            &[],
            &[],
            &b2,
            &test_timing(),
        )
        .unwrap();
        let stale_now = std::fs::read_dir(&ev_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("verify-{id}-stale-"))
            })
            .count();
        assert_eq!(
            stale_now, 1,
            "identical bindings must refresh in place, not preserve again"
        );

        let _ = std::fs::remove_dir_all(&repo.root);
    }

    #[test]
    fn created_at_field_written_to_summary() {
        // 取证时间戳是 summary 字段而非 id 分量（id 必须可引用、可复现）。
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let s = created_at_iso8601();
        assert_eq!(s.len(), 24, "YYYY-MM-DDThh:mm:ss.mmmZ");
        assert!(s.ends_with('Z'));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        // 2000-02-29（闰日）= epoch day 11016。
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        let _ = repo;
    }

    #[test]
    fn write_evidence_includes_timing() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let base = Config::load(&repo).expect("config must load");
        let tmp =
            std::env::temp_dir().join(format!("harness-evidence-timing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config = Config {
            evidence_dir: tmp.join("evidence"),
            ..base
        };
        let bindings = Bindings::current(&repo, &config);
        let gates = vec![Gate::ok("whitespace", "ok")];
        let scenarios = vec![ScenarioResult {
            id: "s.one".to_string(),
            carrier: crate::scenario::Carrier::Engineering,
            verdict: "PASS".to_string(),
            detail: "ok".to_string(),
            duration_ms: 5,
            timed_out: false,
        }];
        let timing = VerifyTiming {
            total_ms: 42,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            deadline_ms: Some(7_200_000),
            deadline_exceeded: false,
            prebuild_ms: 7,
        };
        let id = write_evidence(
            &repo,
            &config,
            "PASS",
            "timing test",
            &gates,
            &scenarios,
            &bindings,
            &timing,
        )
        .unwrap();
        let dir = config.evidence_dir.join(format!("verify-{id}"));
        let summary: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(summary["timing"]["total_ms"], json!(42));
        assert_eq!(
            summary["timing"]["started_at"],
            json!("2026-01-01T00:00:00.000Z")
        );
        assert_eq!(summary["timing"]["deadline_ms"], json!(7_200_000));
        assert_eq!(summary["timing"]["deadline_exceeded"], json!(false));
        assert_eq!(summary["timing"]["prebuild_ms"], json!(7));
        let checks: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        assert_eq!(checks["gates"][0]["duration_ms"], json!(0));
        assert_eq!(checks["gates"][0]["timed_out"], json!(false));
        assert_eq!(checks["gates"][0]["skipped_by_deadline"], json!(false));
        assert_eq!(checks["scenarios"][0]["duration_ms"], json!(5));
        assert_eq!(checks["scenarios"][0]["timed_out"], json!(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn carrier_result(id: &str, carrier: Carrier) -> ScenarioResult {
        ScenarioResult {
            id: id.to_string(),
            carrier,
            verdict: "PASS".to_string(),
            detail: "ok".to_string(),
            duration_ms: 1,
            timed_out: false,
        }
    }

    #[test]
    fn evidence_header_carrier_fields() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let base = Config::load(&repo).expect("config must load");
        let tmp = std::env::temp_dir().join(format!("harness-ev-carrier-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config = Config {
            evidence_dir: tmp.join("evidence"),
            ..base
        };
        let bindings = bindings("rev-carrier");
        let gates = vec![Gate::ok("whitespace", "ok")];
        let timing = VerifyTiming {
            total_ms: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            deadline_ms: None,
            deadline_exceeded: false,
            prebuild_ms: 0,
        };

        // 空场景切片：不写 carriers / carrier_coverage（避免 0/0/0 被误读为全覆盖）。
        let id = write_evidence(
            &repo,
            &config,
            "PASS",
            "empty",
            &gates,
            &[],
            &bindings,
            &timing,
        )
        .unwrap();
        let dir = config.evidence_dir.join(format!("verify-{id}"));
        let summary: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("summary.json")).unwrap())
                .unwrap();
        assert!(summary.get("carriers").is_none(), "{summary}");
        assert!(summary.get("carrier_coverage").is_none(), "{summary}");
        let _ = std::fs::remove_dir_all(&tmp);

        // 非空：字段齐全，且 gates.json.scenarios[].carrier 透传。
        std::fs::create_dir_all(&tmp).unwrap();
        let scenarios = vec![
            carrier_result("a", Carrier::V9Connectivity),
            carrier_result("b", Carrier::N1Fabric),
            carrier_result("c", Carrier::N1Fabric),
            carrier_result("d", Carrier::SharedLeaf),
            carrier_result("e", Carrier::Engineering),
            carrier_result("f", Carrier::External),
        ];
        let id = write_evidence(
            &repo,
            &config,
            "PASS",
            "non-empty",
            &gates,
            &scenarios,
            &bindings,
            &timing,
        )
        .unwrap();
        let dir = config.evidence_dir.join(format!("verify-{id}"));
        let summary: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(summary["carriers"]["v9-connectivity"], json!(1));
        assert_eq!(summary["carriers"]["n1-fabric"], json!(2));
        assert_eq!(summary["carriers"]["shared-leaf"], json!(1));
        assert_eq!(summary["carriers"]["engineering"], json!(1));
        assert_eq!(summary["carriers"]["external"], json!(1));
        assert_eq!(
            summary["carrier_coverage"],
            json!({"scenarios_total": 6, "declared": 6, "missing": 0})
        );
        let checks: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        assert_eq!(checks["scenarios"][1]["carrier"], json!("n1-fabric"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// AC-14 的 P4 期内 fast 代理：用真实仓库 346 场景构造结果，验证
    /// `carrier_coverage` 为 346/346/0、五值求和 == 346、gates carrier ∈ 闭集。
    #[test]
    fn evidence_header_carrier_coverage_matches_repo_scenarios() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let base = Config::load(&repo).expect("config must load");
        let loaded = crate::scenario::load_all(
            &base.scenarios_dir,
            &["product", "engineering", "platform", "regression"],
        );
        assert_eq!(loaded.len(), 346, "repository scenario count");
        let scenarios: Vec<ScenarioResult> = loaded
            .iter()
            .map(|s| carrier_result(&s.id, s.carrier))
            .collect();
        let tmp = std::env::temp_dir().join(format!("harness-ev-coverage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config = Config {
            evidence_dir: tmp.join("evidence"),
            ..base
        };
        let bindings = Bindings::current(&repo, &config);
        let gates = vec![Gate::ok("product-scenarios", "ok")];
        let timing = VerifyTiming {
            total_ms: 1,
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            deadline_ms: None,
            deadline_exceeded: false,
            prebuild_ms: 0,
        };
        let id = write_evidence(
            &repo, &config, "PASS", "coverage", &gates, &scenarios, &bindings, &timing,
        )
        .unwrap();
        let dir = config.evidence_dir.join(format!("verify-{id}"));
        let summary: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(
            summary["carrier_coverage"],
            json!({"scenarios_total": 346, "declared": 346, "missing": 0})
        );
        assert_eq!(summary["carriers"]["v9-connectivity"], json!(191));
        assert_eq!(summary["carriers"]["n1-fabric"], json!(117));
        assert_eq!(summary["carriers"]["shared-leaf"], json!(1));
        assert_eq!(summary["carriers"]["engineering"], json!(29));
        assert_eq!(summary["carriers"]["external"], json!(8));
        let sum: u64 = summary["carriers"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum();
        assert_eq!(sum, 346, "five carrier values must sum to 346");

        let checks: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("gates.json")).unwrap())
                .unwrap();
        let closed: Vec<Value> = Carrier::ALL.iter().map(|c| json!(c.as_str())).collect();
        for s in checks["scenarios"].as_array().unwrap() {
            let c = s["carrier"].clone();
            assert!(closed.contains(&c), "carrier {c} not in closed set");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
