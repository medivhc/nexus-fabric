//! Load machine configuration: harness.toml paths + policies/quality.toml gates.

use crate::env::Repo;
use crate::gates::GateBudget;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_GATE_MS: u64 = 900_000;
const DEFAULT_FULL_DEADLINE_MS: u64 = 7_200_000;
const DEFAULT_SANDBOX_MS: u64 = 180_000;
const DEFAULT_REAL_DEVICE_MS: u64 = 600_000;
const DEFAULT_DRAIN_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug)]
pub struct ScenarioTimeouts {
    pub sandbox: Duration,
    pub real_device: Duration,
    pub drain: Duration,
}

impl ScenarioTimeouts {
    /// `scenario run` 机器接口沿用的旧语义：主命令与 fixture 600s、drain 10s。
    pub fn legacy() -> ScenarioTimeouts {
        ScenarioTimeouts {
            sandbox: Duration::from_secs(600),
            real_device: Duration::from_secs(600),
            drain: Duration::from_secs(10),
        }
    }
    pub fn for_scenario(&self, s: &crate::scenario::Scenario) -> Duration {
        match crate::scenario::scenario_requires(s) {
            "real-device" => self.real_device,
            _ => self.sandbox,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifyTimeouts {
    pub default_gate: Duration,
    pub full_deadline: Option<Duration>,
    pub gates: BTreeMap<String, Duration>,
    pub scenarios: ScenarioTimeouts,
}

impl VerifyTimeouts {
    pub(crate) fn defaults() -> VerifyTimeouts {
        VerifyTimeouts {
            default_gate: Duration::from_millis(DEFAULT_GATE_MS),
            full_deadline: Some(Duration::from_millis(DEFAULT_FULL_DEADLINE_MS)),
            gates: BTreeMap::new(),
            scenarios: ScenarioTimeouts {
                sandbox: Duration::from_millis(DEFAULT_SANDBOX_MS),
                real_device: Duration::from_millis(DEFAULT_REAL_DEVICE_MS),
                drain: Duration::from_millis(DEFAULT_DRAIN_MS),
            },
        }
    }
}

pub struct Config {
    pub policies_dir: PathBuf,
    pub scenarios_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub crates_dir: PathBuf,
    pub engineering_dir: PathBuf,
    /// policies/quality.toml (gate lists for fast/full verification).
    pub quality: Value,
    /// harness.toml [portable_core].crates (WASI/portability gate targets).
    pub portable_core: Vec<String>,
    /// harness.toml [evidence].bind_working_tree_digest —— 该标志此前是
    /// 死配置（源码零读取）。现由 `Bindings::current` 兑现：false 时
    /// bindings 的 digest 字段写 `"unbound"`（status/explain JSON 可见），
    /// true（缺省）时按内容绑定语义计算。
    pub bind_working_tree_digest: bool,
    /// policies/quality.toml [verification.timeouts] + NEXUS_VERIFY_DEADLINE_MS。
    pub verify_timeouts: VerifyTimeouts,
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

/// 合法门名全集：硬编码 `whitespace` + quality.toml 的 fast/full 声明并集
/// （去重、保序）。不得只读 quality.toml，否则 `whitespace` 会被误判。
pub(crate) fn allowed_gate_names(quality: &Value) -> Vec<String> {
    let mut out: Vec<String> = vec!["whitespace".to_string()];
    for level in ["fast", "full"] {
        if let Some(arr) = quality
            .pointer(&format!("/verification/{level}/gates"))
            .and_then(Value::as_array)
        {
            for gate in arr.iter().filter_map(Value::as_str) {
                if !out.iter().any(|existing| existing == gate) {
                    out.push(gate.to_string());
                }
            }
        }
    }
    out
}

fn timeout_value_error(section: &str, field: &str, expected: &str, got: &Value) -> String {
    format!(
        "invalid timeout configuration: policies/quality.toml [{section}].{field}: expected {expected}, got {got}"
    )
}

fn parse_ms(section: &str, field: &str, value: &Value, min: u64) -> Result<u64, String> {
    let expected = if min == 0 {
        "integer >= 0"
    } else {
        "integer >= 1"
    };
    match value.as_u64() {
        Some(n) if n >= min => Ok(n),
        _ => Err(timeout_value_error(section, field, expected, value)),
    }
}

fn parse_verify_timeouts(quality: &Value) -> Result<VerifyTimeouts, String> {
    let mut out = VerifyTimeouts::defaults();
    let Some(section) = quality.pointer("/verification/timeouts") else {
        return Ok(out);
    };
    let Some(table) = section.as_object() else {
        return Err(format!(
            "invalid timeout configuration: policies/quality.toml [verification.timeouts]: expected table, got {section}"
        ));
    };
    if let Some(v) = table.get("default_gate_ms") {
        out.default_gate =
            Duration::from_millis(parse_ms("verification.timeouts", "default_gate_ms", v, 1)?);
    }
    if let Some(v) = table.get("full_deadline_ms") {
        let ms = parse_ms("verification.timeouts", "full_deadline_ms", v, 0)?;
        out.full_deadline = if ms == 0 {
            None
        } else {
            Some(Duration::from_millis(ms))
        };
    }
    if let Some(gates) = table.get("gates") {
        let Some(gates) = gates.as_object() else {
            return Err(format!(
                "invalid timeout configuration: policies/quality.toml [verification.timeouts.gates]: expected table, got {gates}"
            ));
        };
        let allowed = allowed_gate_names(quality);
        for (name, value) in gates {
            if !allowed.iter().any(|a| a == name) {
                return Err(format!(
                    "invalid timeout configuration: policies/quality.toml [verification.timeouts.gates.{name}]: unknown gate name; declared gates: {}",
                    allowed.join(", ")
                ));
            }
            let ms = parse_ms("verification.timeouts.gates", name, value, 1)?;
            out.gates.insert(name.clone(), Duration::from_millis(ms));
        }
    }
    if let Some(scenarios) = table.get("scenarios") {
        let Some(scenarios) = scenarios.as_object() else {
            return Err(format!(
                "invalid timeout configuration: policies/quality.toml [verification.timeouts.scenarios]: expected table, got {scenarios}"
            ));
        };
        if let Some(v) = scenarios.get("sandbox_ms") {
            out.scenarios.sandbox = Duration::from_millis(parse_ms(
                "verification.timeouts.scenarios",
                "sandbox_ms",
                v,
                1,
            )?);
        }
        if let Some(v) = scenarios.get("real_device_ms") {
            out.scenarios.real_device = Duration::from_millis(parse_ms(
                "verification.timeouts.scenarios",
                "real_device_ms",
                v,
                1,
            )?);
        }
        if let Some(v) = scenarios.get("drain_ms") {
            out.scenarios.drain = Duration::from_millis(parse_ms(
                "verification.timeouts.scenarios",
                "drain_ms",
                v,
                1,
            )?);
        }
    }
    Ok(out)
}

/// `NEXUS_VERIFY_DEADLINE_MS` 覆盖配置：`0` = 关闭；非法值 fail-closed。
fn apply_deadline_env(timeouts: VerifyTimeouts) -> Result<VerifyTimeouts, String> {
    apply_deadline_value(timeouts, std::env::var("NEXUS_VERIFY_DEADLINE_MS").ok())
}

fn apply_deadline_value(
    mut timeouts: VerifyTimeouts,
    raw: Option<String>,
) -> Result<VerifyTimeouts, String> {
    let Some(raw) = raw else {
        return Ok(timeouts);
    };
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && !trimmed.starts_with('-')
        && trimmed.chars().all(|c| c.is_ascii_digit());
    if !valid {
        return Err(format!(
            "NEXUS_VERIFY_DEADLINE_MS: expected non-negative integer, got {raw}"
        ));
    }
    let ms: u64 = trimmed.parse().map_err(|_| {
        format!("NEXUS_VERIFY_DEADLINE_MS: expected non-negative integer, got {raw}")
    })?;
    timeouts.full_deadline = if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    };
    Ok(timeouts)
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
        let portable_core = harness
            .pointer("/portable_core/crates")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let bind_working_tree_digest = harness
            .pointer("/evidence/bind_working_tree_digest")
            .and_then(Value::as_bool)
            // 缺省取"绑定"：AGENTS.md §20 无条件要求 working tree digest 在
            // 绑定内，未声明等于放弃绑定是反向安全。
            .unwrap_or(true);
        let verify_timeouts = apply_deadline_env(parse_verify_timeouts(&quality)?)?;
        Ok(Config {
            policies_dir,
            scenarios_dir,
            evidence_dir,
            crates_dir,
            engineering_dir,
            quality,
            portable_core,
            bind_working_tree_digest,
            verify_timeouts,
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

    /// 该门的有效预算 = min(门预算, 全局剩余)。`integration` /
    /// `selected-concurrency` 未显式配置时复用 `workspace-tests` 预算（共享执行）。
    pub fn gate_budget(&self, gate_name: &str, global: GateBudget) -> GateBudget {
        gate_budget_for(&self.verify_timeouts, gate_name, global)
    }
}

/// 预算计算的无状态形式：供门编排（不持有 Config 的单测）复用。
pub(crate) fn gate_budget_for(
    timeouts: &VerifyTimeouts,
    gate_name: &str,
    global: GateBudget,
) -> GateBudget {
    let gate = if let Some(d) = timeouts.gates.get(gate_name) {
        *d
    } else if matches!(gate_name, "integration" | "selected-concurrency") {
        timeouts
            .gates
            .get("workspace-tests")
            .copied()
            .unwrap_or(timeouts.default_gate)
    } else {
        timeouts.default_gate
    };
    let effective = match global.remaining() {
        Some(remaining) => gate.min(remaining),
        None => gate,
    };
    GateBudget::from_limit(Some(effective))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn real_quality() -> Value {
        let repo = Repo::discover().expect("tests run inside the nexus repository");
        toml_file_to_json(
            repo.resolve("policies/quality.toml"),
            "policies/quality.toml",
        )
        .expect("quality.toml must parse")
    }

    #[test]
    fn config_timeouts_default_when_section_absent() {
        let t = parse_verify_timeouts(&json!({})).expect("absent section is valid");
        assert_eq!(t.default_gate, Duration::from_millis(900_000));
        assert_eq!(t.full_deadline, Some(Duration::from_millis(7_200_000)));
        assert_eq!(t.scenarios.sandbox, Duration::from_millis(180_000));
        assert_eq!(t.scenarios.real_device, Duration::from_millis(600_000));
        assert_eq!(t.scenarios.drain, Duration::from_millis(10_000));
        assert!(t.gates.is_empty());
    }

    #[test]
    fn config_timeouts_partial_section_uses_defaults() {
        let t = parse_verify_timeouts(&json!({
            "verification": {"timeouts": {"default_gate_ms": 5_000}}
        }))
        .expect("partial section is valid");
        assert_eq!(t.default_gate, Duration::from_millis(5_000));
        assert_eq!(t.full_deadline, Some(Duration::from_millis(7_200_000)));
        assert_eq!(t.scenarios.sandbox, Duration::from_millis(180_000));
        assert!(t.gates.is_empty());
    }

    #[test]
    fn config_timeouts_reject_bad_values() {
        let cases = [
            (
                json!({"verification": {"timeouts": {"default_gate_ms": 0}}}),
                "invalid timeout configuration: policies/quality.toml [verification.timeouts].default_gate_ms: expected integer >= 1, got 0",
            ),
            (
                json!({"verification": {"timeouts": {"default_gate_ms": -1}}}),
                "invalid timeout configuration: policies/quality.toml [verification.timeouts].default_gate_ms: expected integer >= 1, got -1",
            ),
            (
                json!({"verification": {"timeouts": {"default_gate_ms": "abc"}}}),
                "invalid timeout configuration: policies/quality.toml [verification.timeouts].default_gate_ms: expected integer >= 1, got \"abc\"",
            ),
            (
                json!({"verification": {"timeouts": {"full_deadline_ms": 1.5}}}),
                "invalid timeout configuration: policies/quality.toml [verification.timeouts].full_deadline_ms: expected integer >= 0, got 1.5",
            ),
            (
                json!({"verification": {"timeouts": {"scenarios": {"sandbox_ms": 0}}}}),
                "invalid timeout configuration: policies/quality.toml [verification.timeouts.scenarios].sandbox_ms: expected integer >= 1, got 0",
            ),
        ];
        for (quality, expected) in cases {
            assert_eq!(
                parse_verify_timeouts(&quality).unwrap_err(),
                expected,
                "quality: {quality}"
            );
        }
    }

    #[test]
    fn config_timeouts_reject_unknown_gate() {
        let mut quality = real_quality();
        quality["verification"]["timeouts"] = json!({"gates": {"typo": 1}});
        let err = parse_verify_timeouts(&quality).unwrap_err();
        assert!(
            err.starts_with(
                "invalid timeout configuration: policies/quality.toml [verification.timeouts.gates.typo]: unknown gate name; declared gates: "
            ),
            "{err}"
        );
        let declared = err.split("declared gates: ").nth(1).unwrap();
        assert_eq!(declared.split(", ").count(), 23, "{declared}");
    }

    #[test]
    fn allowed_gate_names_is_23_and_includes_whitespace() {
        let names = allowed_gate_names(&real_quality());
        assert_eq!(names.len(), 23);
        assert_eq!(names.first().map(String::as_str), Some("whitespace"));
        assert!(!names.iter().any(|n| n == "integrations-no-such"));
        assert!(names.iter().any(|n| n == "product-scenarios"));
    }

    #[test]
    fn env_deadline_override() {
        let base = VerifyTimeouts::defaults();
        assert_eq!(
            apply_deadline_value(base.clone(), Some("0".to_string()))
                .unwrap()
                .full_deadline,
            None
        );
        assert_eq!(
            apply_deadline_value(base.clone(), Some(" 123 ".to_string()))
                .unwrap()
                .full_deadline,
            Some(Duration::from_millis(123))
        );
        for bad in ["abc", "-1", "", "1.5"] {
            assert_eq!(
                apply_deadline_value(base.clone(), Some(bad.to_string())).unwrap_err(),
                format!("NEXUS_VERIFY_DEADLINE_MS: expected non-negative integer, got {bad}"),
                "value {bad:?}"
            );
        }
        assert_eq!(
            apply_deadline_value(base, None).unwrap().full_deadline,
            Some(Duration::from_millis(7_200_000))
        );
    }

    #[test]
    fn gate_budget_takes_min_of_gate_and_global() {
        let mut t = VerifyTimeouts::defaults();
        t.gates
            .insert("check".to_string(), Duration::from_millis(100));
        let global = GateBudget::from_limit(Some(Duration::from_millis(50)));
        let budget = gate_budget_for(&t, "check", global);
        let remaining = budget.remaining().expect("bounded budget");
        assert!(remaining <= Duration::from_millis(50), "{remaining:?}");
        assert!(!remaining.is_zero(), "{remaining:?}");
    }
}
