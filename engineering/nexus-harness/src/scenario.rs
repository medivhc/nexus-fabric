//! Scenario contracts: parse scenarios/**/*.toml and execute the ones that
//! declare a [when].command, evaluating [[expect]] entries against the JSON
//! output. Scenarios without a command are static contracts (recorded UNKNOWN).

use crate::config::{Config, ScenarioTimeouts};
use crate::env::{Repo, cargo_metadata};
use crate::gates::{CommandOutcome, Gate, GateBudget, run_bounded};
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
    /// 「字段缺失或为 JSON null」。TOML 没有 null 字面量，
    /// `equals = null` 会直接让整个文件解析失败而被静默跳过
    /// （node_priority / traffic_stats 两个场景即此故障，2026-10-18）。
    /// 断言"返回 None"这类语义必须用 `absent = true` 表达，
    /// 不得因缺少表达手段而删掉断言。
    Absent,
}

/// 场景的执行载体所属栈（契约 §2 / 冻结件 §4.2 闭集 5 值）。
///
/// 非 `Option`：`load_file` 成功即已解析并校验过声明值与派生值一致，
/// 因此下游（证据头、索引）不需要再处理"未声明"分支。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Carrier {
    V9Connectivity,
    N1Fabric,
    SharedLeaf,
    Engineering,
    External,
}

impl Carrier {
    pub const ALL: [Carrier; 5] = [
        Carrier::V9Connectivity,
        Carrier::N1Fabric,
        Carrier::SharedLeaf,
        Carrier::Engineering,
        Carrier::External,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Carrier::V9Connectivity => "v9-connectivity",
            Carrier::N1Fabric => "n1-fabric",
            Carrier::SharedLeaf => "shared-leaf",
            Carrier::Engineering => "engineering",
            Carrier::External => "external",
        }
    }

    /// 闭集解析（大小写敏感、逐字匹配）。非法值返回 `None`，由调用方报错。
    pub fn parse(s: &str) -> Option<Carrier> {
        Carrier::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// 从 `[when].command` 文本派生 carrier（冻结件 §4.2 十条规则，按序命中即止）。
///
/// `None` = 不命中任何规则（合成夹具容忍；仓库级 totality 由
/// `scenario index --check` 强制）。
pub fn carrier_for_command(command: &str) -> Option<Carrier> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let first = *tokens.first()?;
    let package = package_token(&tokens);
    let run_sub = harness_run_subcommand(&tokens, package);
    const V9_RUN: [&str; 7] = [
        "virtual-subnet-tunnel",
        "virtual-subnet-mesh",
        "multihop-routing",
        "mesh-dns",
        "firewall-rules",
        "bandwidth-qos",
        "auto-reconnect",
    ];
    const N1_RUN: [&str; 3] = ["dns-unified", "multipath", "nat-hole-punching"];

    // ① harness `run bootstrap-join`（结构化判定：不是任意文本子串）。
    if run_sub == Some("bootstrap-join") {
        return Some(Carrier::V9Connectivity);
    }
    // ② `-p nexus`（**token 精确匹配**，非前缀）或 CLI 裸命令。
    if package == Some("nexus") || matches!(first, "proxy" | "virtual") {
        return Some(Carrier::V9Connectivity);
    }
    // ③ harness run ∈ v9 内联子命令集。
    if run_sub.is_some_and(|s| V9_RUN.contains(&s)) {
        return Some(Carrier::V9Connectivity);
    }
    // ④ `-p nexusd`。
    if package == Some("nexusd") {
        return Some(Carrier::N1Fabric);
    }
    // ⑤ `-p nexus-<name>`（<name> ≠ harness）。
    if package.is_some_and(|p| p.starts_with("nexus-") && p != "nexus-harness") {
        return Some(Carrier::N1Fabric);
    }
    // ⑥ harness run ∈ n1 内联子命令集。
    if run_sub.is_some_and(|s| N1_RUN.contains(&s)) {
        return Some(Carrier::N1Fabric);
    }
    // ⑦ harness run qos-cake（两栈共享叶）。
    if run_sub == Some("qos-cake") {
        return Some(Carrier::SharedLeaf);
    }
    // ⑧ `-p nexus-harness`。
    if package == Some("nexus-harness") {
        return Some(Carrier::Engineering);
    }
    // ⑨ 首 token 是 harness 自身。
    if first_basename(&tokens) == Some("nexus-harness") {
        return Some(Carrier::Engineering);
    }
    // ⑩ 脚本载体：解释器首 token 或仓库内 `scripts/**.sh` 路径。
    if matches!(first, "python3" | "python" | "sh" | "bash") || is_scripts_sh(first) {
        return Some(Carrier::External);
    }
    None
}

/// `-p` / `--package` 的**下一个 token**（包名），不是字符串前缀匹配。
fn package_token<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    tokens
        .windows(2)
        .find(|w| matches!(w[0], "-p" | "--package"))
        .map(|w| w[1])
}

fn first_basename<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    tokens
        .first()
        .and_then(|t| Path::new(*t).file_name()?.to_str())
}

/// harness `run <sub>` 子命令名。识别两种调用形态：
/// `nexus-harness run <sub>` 与 `cargo … -p nexus-harness … -- run <sub>`。
fn harness_run_subcommand<'a>(tokens: &[&'a str], package: Option<&str>) -> Option<&'a str> {
    if first_basename(tokens) == Some("nexus-harness") {
        return match tokens.get(1) {
            Some(&"run") => tokens.get(2).copied(),
            _ => None,
        };
    }
    if tokens.first() == Some(&"cargo") && package == Some("nexus-harness") {
        if let Some(pos) = tokens.iter().position(|t| *t == "--") {
            if tokens.get(pos + 1) == Some(&"run") {
                return tokens.get(pos + 2).copied();
            }
        }
    }
    None
}

fn is_scripts_sh(token: &str) -> bool {
    (token.starts_with("scripts/") || token.contains("/scripts/")) && token.ends_with(".sh")
}

fn legal_carriers() -> String {
    Carrier::ALL
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone)]
pub struct Scenario {
    pub id: String,
    /// toml 所在子目录（product | regression | platform | engineering）。
    pub subdir: String,
    /// toml 的 `title` 字段原文（缺省为空字符串）。
    pub title: String,
    /// 顶层 `requires_root = true`（缺省 false）。
    pub requires_root: bool,
    /// 文件 stem（小写），供 requires 启发式使用。
    pub file_stem: String,
    pub platform: Option<String>,
    /// E4 夹具命令（P0-6）：harness 在执行 `[when].command` 之前按序执行，
    /// 全部 exit 0 才继续；任一失败则场景判 FAIL（夹具是场景 E4 环境声明的
    /// 一部分，不是独立的测试）。声明于 `[given].fixture`（字符串数组）。
    pub fixtures: Vec<String>,
    pub command: Option<String>,
    pub expects: Vec<ScenarioExpect>,
    /// 顶层 `evidence_strength` 声明原文（契约 §2：E1–E5，可选）。
    /// None = 未声明或非字符串；分层由 `evidence_strength()` 推导/校验，
    /// 加载不因该字段缺失或非法而失败（契约 §4.5：不静默丢弃场景）。
    pub evidence_strength: Option<String>,
    /// 顶层 `carrier`（契约 §2）：执行载体所属栈，闭集 5 值。
    /// `load_file` 成功即保证已声明且与派生值一致。
    pub carrier: Carrier,
}

#[derive(Clone)]
pub struct ScenarioResult {
    pub id: String,
    pub carrier: Carrier,
    pub verdict: String,
    pub detail: String,
    pub duration_ms: u64,
    pub timed_out: bool,
}

/// `cargo run --example <name>` 的产物键：features 为规范化（排序去重）集合，
/// `locked` 参与键，避免 `--locked` 与非 `--locked` 复用同一预编结果。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ExampleKey {
    pub package: String,
    pub example: String,
    pub features: Vec<String>,
    pub locked: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BinKey {
    pub package: String,
    pub bin: String,
    pub features: Vec<String>,
    pub locked: bool,
}

pub struct ArtifactBuildFailure {
    pub package: String,
    pub kind: String,
    pub target: String,
    pub detail: String,
}

#[derive(Default)]
pub struct ScenarioArtifacts {
    pub examples: std::collections::BTreeMap<ExampleKey, PathBuf>,
    pub bins: std::collections::BTreeMap<BinKey, PathBuf>,
    pub failures: Vec<ArtifactBuildFailure>,
    /// 场景引用但 metadata 中**不存在**的 target（如 contract-first 的
    /// `nexusd --example n3_task_e4`）。不预编、不判 prebuild 失败；
    /// 运行时保留基线语义（n3 → UNKNOWN）。
    pub missing: Vec<(String, String, String)>,
    pub build_ms: u64,
}

pub enum ResolvedCommand {
    Direct {
        program: PathBuf,
        args: Vec<String>,
        current_dir: Option<PathBuf>,
    },
    Unchanged {
        command: String,
    },
    Unavailable {
        reason: String,
    },
    MissingTarget {
        package: String,
        kind: String,
        target: String,
    },
}

struct ParsedCargoRun {
    package: String,
    example: Option<String>,
    bin: Option<String>,
    features: Vec<String>,
    locked: bool,
    args: Vec<String>,
}

fn normalize_features(raw: &str) -> Vec<String> {
    let mut features: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    features.sort();
    features.dedup();
    features
}

/// 只接受整条命令就是 `cargo run ...` 的形态；shell 组合（`cd`/`&&`/管道/
/// 命令替换）、env 前缀、`--release` 或未知 cargo flag 一律返回 None →
/// 调用方走旧路径（宁可慢，不猜语义）。
fn parse_cargo_run(command: &str) -> Option<ParsedCargoRun> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.first() != Some(&"cargo") {
        return None;
    }
    if tokens
        .iter()
        .any(|t| t.contains('`') || t.contains("$(") || matches!(*t, "&&" | "||" | "|" | ";"))
    {
        return None;
    }
    if tokens.get(1) != Some(&"run") {
        return None;
    }
    let mut package: Option<String> = None;
    let mut example: Option<String> = None;
    let mut bin: Option<String> = None;
    let mut features: Vec<String> = Vec::new();
    let mut locked = false;
    let mut args: Vec<String> = Vec::new();
    let mut i = 2;
    while i < tokens.len() {
        let token = tokens[i];
        if token == "--" {
            args = tokens[i + 1..].iter().map(|s| s.to_string()).collect();
            break;
        }
        if token == "--quiet" || token == "-q" {
            i += 1;
            continue;
        }
        if token == "--locked" {
            locked = true;
            i += 1;
            continue;
        }
        if token == "-p" || token == "--package" {
            package = Some(tokens.get(i + 1)?.to_string());
            i += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--package=") {
            package = Some(v.to_string());
            i += 1;
            continue;
        }
        if token == "--example" {
            example = Some(tokens.get(i + 1)?.to_string());
            i += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--example=") {
            example = Some(v.to_string());
            i += 1;
            continue;
        }
        if token == "--bin" {
            bin = Some(tokens.get(i + 1)?.to_string());
            i += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--bin=") {
            bin = Some(v.to_string());
            i += 1;
            continue;
        }
        if token == "--features" {
            features = normalize_features(tokens.get(i + 1)?);
            i += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--features=") {
            features = normalize_features(v);
            i += 1;
            continue;
        }
        return None;
    }
    if example.is_some() && bin.is_some() {
        return None;
    }
    Some(ParsedCargoRun {
        package: package?,
        example,
        bin,
        features,
        locked,
        args,
    })
}

fn artifact_failure<'a>(
    artifacts: &'a ScenarioArtifacts,
    kind: &str,
    package: &str,
    target: &str,
) -> Option<&'a ArtifactBuildFailure> {
    artifacts
        .failures
        .iter()
        .find(|f| f.kind == kind && f.package == package && f.target == target)
}

fn is_missing(artifacts: &ScenarioArtifacts, kind: &str, package: &str, target: &str) -> bool {
    artifacts
        .missing
        .iter()
        .any(|(k, p, t)| k == kind && p == package && t == target)
}

pub fn resolve_scenario_command(command: &str, artifacts: &ScenarioArtifacts) -> ResolvedCommand {
    let Some(parsed) = parse_cargo_run(command) else {
        return ResolvedCommand::Unchanged {
            command: command.to_string(),
        };
    };
    if let Some(example) = parsed.example {
        let key = ExampleKey {
            package: parsed.package.clone(),
            example: example.clone(),
            features: parsed.features,
            locked: parsed.locked,
        };
        return match artifacts.examples.get(&key) {
            Some(path) => ResolvedCommand::Direct {
                program: path.clone(),
                args: parsed.args,
                current_dir: None,
            },
            None => {
                if is_missing(artifacts, "example", &parsed.package, &example) {
                    ResolvedCommand::MissingTarget {
                        package: parsed.package,
                        kind: "example".to_string(),
                        target: example,
                    }
                } else if let Some(failure) =
                    artifact_failure(artifacts, "example", &parsed.package, &example)
                {
                    ResolvedCommand::Unavailable {
                        reason: format!("{}:example:{example}\n{}", parsed.package, failure.detail),
                    }
                } else {
                    // 未预编（如不同的 --locked/features 变体）→ 旧路径。
                    ResolvedCommand::Unchanged {
                        command: command.to_string(),
                    }
                }
            }
        };
    }
    if let Some(bin) = parsed.bin {
        let key = BinKey {
            package: parsed.package.clone(),
            bin: bin.clone(),
            features: parsed.features,
            locked: parsed.locked,
        };
        return match artifacts.bins.get(&key) {
            Some(path) => ResolvedCommand::Direct {
                program: path.clone(),
                args: parsed.args,
                current_dir: None,
            },
            None => {
                if is_missing(artifacts, "bin", &parsed.package, &bin) {
                    ResolvedCommand::MissingTarget {
                        package: parsed.package,
                        kind: "bin".to_string(),
                        target: bin,
                    }
                } else if let Some(failure) =
                    artifact_failure(artifacts, "bin", &parsed.package, &bin)
                {
                    ResolvedCommand::Unavailable {
                        reason: format!("{}:bin:{bin}\n{}", parsed.package, failure.detail),
                    }
                } else {
                    ResolvedCommand::Unchanged {
                        command: command.to_string(),
                    }
                }
            }
        };
    }
    // 无 `--example`/`--bin`：cargo 选择包内唯一 bin（feature 组合参与键）。
    // 无法唯一确定时回退旧路径（绝不猜 target）。
    let mut candidates: Vec<&BinKey> = artifacts
        .bins
        .keys()
        .filter(|k| {
            k.package == parsed.package
                && k.features == parsed.features
                && k.locked == parsed.locked
        })
        .collect();
    if candidates.len() != 1 {
        return ResolvedCommand::Unchanged {
            command: command.to_string(),
        };
    }
    let key = candidates.pop().expect("one candidate").clone();
    match artifacts.bins.get(&key) {
        Some(path) => ResolvedCommand::Direct {
            program: path.clone(),
            args: parsed.args,
            current_dir: None,
        },
        None => ResolvedCommand::Unchanged {
            command: command.to_string(),
        },
    }
}

fn default_bin(meta: &Value, package: &str) -> Option<String> {
    let member_ids: Vec<&str> = meta["workspace_members"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let pkg = meta["packages"].as_array()?.iter().find(|p| {
        p["name"].as_str() == Some(package)
            && p["id"].as_str().is_some_and(|id| member_ids.contains(&id))
    })?;
    let mut bins: Vec<String> = pkg["targets"]
        .as_array()?
        .iter()
        .filter(|t| {
            t["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
        })
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    bins.sort();
    bins.dedup();
    if bins.len() == 1 { bins.pop() } else { None }
}

fn target_declared(meta: &Value, package: &str, kind: &str, name: &str) -> bool {
    let member_ids: Vec<&str> = meta["workspace_members"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    meta["packages"]
        .as_array()
        .and_then(|packages| {
            packages.iter().find(|p| {
                p["name"].as_str() == Some(package)
                    && p["id"].as_str().is_some_and(|id| member_ids.contains(&id))
            })
        })
        .and_then(|p| p["targets"].as_array())
        .is_some_and(|targets| {
            targets.iter().any(|t| {
                t["name"].as_str() == Some(name)
                    && t["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|k| k == kind))
            })
        })
}

type MissingTargets = Vec<(String, String, String)>;
type CollectedKeys = (
    std::collections::BTreeSet<ExampleKey>,
    std::collections::BTreeSet<BinKey>,
    MissingTargets,
);

fn collect_scenario_keys(scenarios: &[Scenario], meta: &Value) -> CollectedKeys {
    let mut examples = std::collections::BTreeSet::new();
    let mut bins = std::collections::BTreeSet::new();
    let mut missing: Vec<(String, String, String)> = Vec::new();
    for scenario in scenarios {
        let mut commands: Vec<&String> = scenario.fixtures.iter().collect();
        if let Some(command) = &scenario.command {
            commands.push(command);
        }
        for command in commands {
            let Some(parsed) = parse_cargo_run(command) else {
                continue;
            };
            if let Some(example) = parsed.example {
                if !target_declared(meta, &parsed.package, "example", &example) {
                    missing.push(("example".to_string(), parsed.package, example));
                    continue;
                }
                examples.insert(ExampleKey {
                    package: parsed.package,
                    example,
                    features: parsed.features,
                    locked: parsed.locked,
                });
                continue;
            }
            if let Some(bin) = parsed.bin {
                if !target_declared(meta, &parsed.package, "bin", &bin) {
                    missing.push(("bin".to_string(), parsed.package, bin));
                    continue;
                }
                bins.insert(BinKey {
                    package: parsed.package,
                    bin,
                    features: parsed.features,
                    locked: parsed.locked,
                });
                continue;
            }
            if let Some(bin) = default_bin(meta, &parsed.package) {
                bins.insert(BinKey {
                    package: parsed.package,
                    bin,
                    features: parsed.features,
                    locked: parsed.locked,
                });
            }
        }
    }
    missing.sort();
    missing.dedup();
    (examples, bins, missing)
}

struct BuildGroup {
    package: String,
    kind: &'static str,
    targets: Vec<String>,
    features: Vec<String>,
    locked: bool,
}

fn build_groups(
    examples: &std::collections::BTreeSet<ExampleKey>,
    bins: &std::collections::BTreeSet<BinKey>,
) -> Vec<BuildGroup> {
    let mut groups: std::collections::BTreeMap<
        (String, &'static str, Vec<String>, bool),
        Vec<String>,
    > = std::collections::BTreeMap::new();
    for key in examples {
        groups
            .entry((
                key.package.clone(),
                "example",
                key.features.clone(),
                key.locked,
            ))
            .or_default()
            .push(key.example.clone());
    }
    for key in bins {
        groups
            .entry((key.package.clone(), "bin", key.features.clone(), key.locked))
            .or_default()
            .push(key.bin.clone());
    }
    groups
        .into_iter()
        .map(|((package, kind, features, locked), mut targets)| {
            targets.sort();
            targets.dedup();
            BuildGroup {
                package,
                kind,
                targets,
                features,
                locked,
            }
        })
        .collect()
}

fn duplicate_targets(
    examples: &std::collections::BTreeSet<ExampleKey>,
    bins: &std::collections::BTreeSet<BinKey>,
) -> std::collections::BTreeSet<(String, String)> {
    let mut packages: std::collections::BTreeMap<
        (String, String),
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    for key in examples {
        packages
            .entry(("example".to_string(), key.example.clone()))
            .or_default()
            .insert(key.package.clone());
    }
    for key in bins {
        packages
            .entry(("bin".to_string(), key.bin.clone()))
            .or_default()
            .insert(key.package.clone());
    }
    packages
        .into_iter()
        .filter(|(_, pkgs)| pkgs.len() > 1)
        .map(|(key, _)| key)
        .collect()
}

fn safe_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// 同名 example 的 per-package 快照路径：cargo 对不同包的同名 example
/// 共用 `target/debug/examples/<name>` 规范路径，直接使用会串包。预编时
/// 强制重建并在同目录复制一份包私有文件（进程内映射，不写跨 run 映射文件）。
fn unique_artifact_path(
    path: &std::path::Path,
    package: &str,
    kind: &str,
    target: &str,
    features: &[String],
    locked: bool,
) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    features.hash(&mut hasher);
    locked.hash(&mut hasher);
    let suffix = hasher.finish();
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    dir.join(format!(
        ".nexus-harness-{}-{}-{}-{suffix:x}",
        safe_component(package),
        kind,
        safe_component(target)
    ))
}

fn force_canonical_relink(meta: &Value, kind: &str, target: &str) {
    if kind != "example" {
        return;
    }
    let Some(dir) = meta["target_directory"]
        .as_str()
        .map(|t| Path::new(t).join("debug/examples"))
    else {
        return;
    };
    let _ = std::fs::remove_file(dir.join(target));
}

fn group_args(group: &BuildGroup) -> Vec<String> {
    let mut args = vec!["build".to_string(), "-p".to_string(), group.package.clone()];
    for target in &group.targets {
        args.push(format!("--{}", group.kind));
        args.push(target.clone());
    }
    if !group.features.is_empty() {
        args.push("--features".to_string());
        args.push(group.features.join(","));
    }
    if group.locked {
        args.push("--locked".to_string());
    }
    args.push("--message-format=json".to_string());
    args
}

fn record_failure(
    artifacts: &mut ScenarioArtifacts,
    group: &BuildGroup,
    target: &str,
    detail: &str,
) {
    let tail: Vec<&str> = detail.lines().rev().take(20).collect();
    let detail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
    artifacts.failures.push(ArtifactBuildFailure {
        package: group.package.clone(),
        kind: group.kind.to_string(),
        target: target.to_string(),
        detail,
    });
}

fn map_group_artifacts(
    group: &BuildGroup,
    meta: &Value,
    repo: &Repo,
    duplicates: &std::collections::BTreeSet<(String, String)>,
    text: &str,
    artifacts: &mut ScenarioArtifacts,
) -> Result<(), String> {
    let member_ids: Vec<&str> = meta["workspace_members"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut mapped = 0usize;
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value["reason"] != "compiler-artifact" || value["profile"]["test"] != false {
            continue;
        }
        let Some(executable) = value["executable"].as_str() else {
            continue;
        };
        let Some(target_name) = value["target"]["name"].as_str() else {
            continue;
        };
        if !group.targets.iter().any(|t| t == target_name) {
            continue;
        }
        let Some(package_id) = value["package_id"].as_str() else {
            continue;
        };
        if !member_ids.contains(&package_id) {
            continue;
        }
        let package_name = meta["packages"]
            .as_array()
            .and_then(|packages| {
                packages
                    .iter()
                    .find(|p| p["id"].as_str() == Some(package_id))
                    .and_then(|p| p["name"].as_str())
            })
            .unwrap_or_default()
            .to_string();
        if package_name != group.package {
            continue;
        }
        let path = repo.root.join(executable);
        if !path.is_file() {
            return Err(format!("executable missing: {}", path.display()));
        }
        let path = if duplicates.contains(&(group.kind.to_string(), target_name.to_string())) {
            let snapshot = unique_artifact_path(
                &path,
                &group.package,
                group.kind,
                target_name,
                &group.features,
                group.locked,
            );
            std::fs::copy(&path, &snapshot)
                .map_err(|e| format!("snapshot artifact {}: {e}", snapshot.display()))?;
            snapshot
        } else {
            path
        };
        if group.kind == "example" {
            artifacts.examples.insert(
                ExampleKey {
                    package: group.package.clone(),
                    example: target_name.to_string(),
                    features: group.features.clone(),
                    locked: group.locked,
                },
                path,
            );
        } else {
            artifacts.bins.insert(
                BinKey {
                    package: group.package.clone(),
                    bin: target_name.to_string(),
                    features: group.features.clone(),
                    locked: group.locked,
                },
                path,
            );
        }
        mapped += 1;
    }
    if mapped == 0 {
        return Err("cargo returned no matching compiler-artifact executables".to_string());
    }
    Ok(())
}

fn run_build_group(
    group: &BuildGroup,
    meta: &Value,
    repo: &Repo,
    duplicates: &std::collections::BTreeSet<(String, String)>,
    budget: GateBudget,
    artifacts: &mut ScenarioArtifacts,
) -> Result<(), String> {
    for target in &group.targets {
        if duplicates.contains(&(group.kind.to_string(), target.clone())) {
            force_canonical_relink(meta, group.kind, target);
        }
    }
    let args = group_args(group);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_bounded(&repo.root, "cargo", &arg_refs, budget) {
        CommandOutcome::Exited {
            success: true,
            text,
        } => map_group_artifacts(group, meta, repo, duplicates, &text, artifacts),
        CommandOutcome::Exited {
            success: false,
            text,
        } => Err(text),
        CommandOutcome::TimedOut { text } => Err(format!(
            "cargo build timed out after {}s\n{text}",
            budget.remaining().map(|d| d.as_secs()).unwrap_or(0)
        )),
        CommandOutcome::SpawnFailed { detail } => Err(detail),
    }
}

/// 预编场景实际引用的 example/bin（一次），只编引用的 target；失败按单个
/// key 重试一次，仍失败写入 failures（fail-closed，不静默跳过场景）。
pub fn prebuild_scenario_artifacts(
    scenarios: &[Scenario],
    repo: &Repo,
    budget: GateBudget,
) -> ScenarioArtifacts {
    use std::time::Instant;
    let started = Instant::now();
    let mut artifacts = ScenarioArtifacts::default();
    let meta = match cargo_metadata() {
        Ok(meta) => meta,
        Err(e) => {
            artifacts.failures.push(ArtifactBuildFailure {
                package: "*".to_string(),
                kind: "*".to_string(),
                target: "*".to_string(),
                detail: format!("cargo metadata failed: {e}"),
            });
            artifacts.build_ms = started.elapsed().as_millis() as u64;
            return artifacts;
        }
    };
    let (examples, bins, missing) = collect_scenario_keys(scenarios, &meta);
    artifacts.missing = missing;
    let duplicates = duplicate_targets(&examples, &bins);
    let groups = build_groups(&examples, &bins);
    for group in groups {
        if budget.expired() {
            for target in &group.targets {
                record_failure(&mut artifacts, &group, target, "prebuild budget exhausted");
            }
            continue;
        }
        if run_build_group(&group, &meta, repo, &duplicates, budget, &mut artifacts).is_ok() {
            continue;
        }
        // 整组失败 → 按单个 key 重试一次，缩小失败影响面（AC9）。
        for target in &group.targets {
            if budget.expired() {
                record_failure(&mut artifacts, &group, target, "prebuild budget exhausted");
                continue;
            }
            let single = BuildGroup {
                package: group.package.clone(),
                kind: group.kind,
                targets: vec![target.clone()],
                features: group.features.clone(),
                locked: group.locked,
            };
            if let Err(detail) =
                run_build_group(&single, &meta, repo, &duplicates, budget, &mut artifacts)
            {
                record_failure(&mut artifacts, &group, target, &detail);
            }
        }
    }
    artifacts.build_ms = started.elapsed().as_millis() as u64;
    artifacts
}

fn load_file(path: &PathBuf, subdir: &str) -> Result<Scenario, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: toml::Value =
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    // schema_version 契约校验（docs/e2e-test-system-contract.md §2）：
    // 缺省或非 1 都拒绝加载，避免旧版/异构场景被静默丢弃。
    let sv = v.get("schema_version").and_then(toml::Value::as_integer);
    if sv != Some(1) {
        return Err(format!(
            "schema_version 校验失败: {:?}（契约要求 schema_version = 1）",
            sv
        ));
    }
    let id = v
        .get("id")
        .ok_or_else(|| format!("缺 id 字段: {}", path.display()))?
        .as_str()
        .ok_or_else(|| format!("id 非字符串: {}", path.display()))?
        .to_string();
    let title = v
        .get("title")
        .and_then(toml::Value::as_str)
        .unwrap_or("")
        .to_string();
    let requires_root = v
        .get("requires_root")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    // 证据分层声明（契约 §2/§3）：可选字符串 E1–E5；缺省或非法时由
    // `evidence_strength()` 推导 / fail-safe 降级，加载不因此失败。
    let evidence_strength = v
        .get("evidence_strength")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let platform = v
        .get("given")
        .and_then(|g| g.get("platform"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    // E4 夹具声明（P0-6）：`[given].fixture = ["cmd1", "cmd2"]`。
    let fixtures: Vec<String> = v
        .get("given")
        .and_then(|g| g.get("fixture"))
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let command = v
        .get("when")
        .and_then(|w| w.get("command"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    // 顶层 carrier（契约 §2）：必填、闭集 5 值，且与命令派生值一致。
    // 缺失/非法/不一致 → Err（fail-closed，由 load_all_reporting 汇总成门 FAIL）。
    let carrier = match v.get("carrier") {
        None => {
            return Err(format!(
                "缺顶层 carrier 字段: {}（合法值: {}）",
                path.display(),
                legal_carriers()
            ));
        }
        Some(toml::Value::String(s)) => Carrier::parse(s).ok_or_else(|| {
            format!(
                "非法 carrier 值 {:?}: {}（合法值: {}）",
                s,
                path.display(),
                legal_carriers()
            )
        })?,
        Some(other) => {
            return Err(format!(
                "carrier 非字符串（{:?}）: {}（合法值: {}）",
                other,
                path.display(),
                legal_carriers()
            ));
        }
    };
    if let Some(cmd) = command.as_deref() {
        if let Some(derived) = carrier_for_command(cmd) {
            if derived != carrier {
                return Err(format!(
                    "carrier 与派生值不一致: {} 声明 {}，命令派生 {}（command: {cmd}）",
                    path.display(),
                    carrier.as_str(),
                    derived.as_str()
                ));
            }
        }
    }
    let expects = v
        .get("expect")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let path = e.get("field")?.as_str()?.to_string();
                    let kind = if let Some(x) = e.get("equals") {
                        ExpectKind::Equals(toml_value_to_json(x))
                    } else if let Some(list) = e.get("one_of").and_then(toml::Value::as_array) {
                        ExpectKind::OneOf(list.iter().map(toml_value_to_json).collect())
                    } else if e.get("non_empty").and_then(toml::Value::as_bool) == Some(true) {
                        ExpectKind::NonEmpty
                    } else if e.get("absent").and_then(toml::Value::as_bool) == Some(true) {
                        ExpectKind::Absent
                    } else {
                        return None;
                    };
                    Some(ScenarioExpect { path, kind })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Scenario {
        id,
        subdir: subdir.to_string(),
        title,
        requires_root,
        file_stem,
        platform,
        fixtures,
        command,
        expects,
        evidence_strength,
        carrier,
    })
}

/// 单场景的执行环境需求（启发式 v1，见 CONTRACT-scenario-pack.md）。
///
/// toml 不可改（Protected），故为推导值：
/// - `requires_root = true` → "real-device"；
/// - 文件 stem 或 id 含 `realnet` / `real_net` → "real-device"；
/// - 其余 → "sandbox"。
pub fn scenario_requires(s: &Scenario) -> &'static str {
    if s.requires_root {
        return "real-device";
    }
    if s.file_stem.contains("realnet")
        || s.file_stem.contains("real_net")
        || s.id.to_lowercase().contains("realnet")
        || s.id.to_lowercase().contains("real_net")
    {
        return "real-device";
    }
    "sandbox"
}

/// 场景的证据分层（契约 §3 分层证据模型 E1–E5），与 `scenario_requires`
/// 的真机/sandbox 二值分层显式关联，供报告层按强度聚合。
///
/// 判定顺序：
/// 1. 显式声明且合法（`E1`–`E5`）→ 原样返回声明值；
/// 2. 显式声明非法（拼错/异构值，如 `e3` / `E9`）→ **fail-safe 降级 E1**：
///    非法声明不得获得比推导更强的强度（与 `load_file` 拒绝
///    `schema_version != 1` 的"不静默接受异构值"同一哲学）；
/// 3. 缺省推导（按 requires / fixture / command 有无；subdir 不单独升级强度——
///    强度取决于场景**实际执行什么**，而非它住在哪个目录）：
///    - `scenario_requires == "real-device"` → `E4`（真机/隔离环境）；
///    - 声明了 `[given].fixture` → `E4`（"scenario + fixture，离线可复现"）；
///    - 有 `[when].command` → `E3`（沙箱场景，harness verify 的
///      product-scenarios gate 执行）；
///    - 静态契约（无 command）→ `E1`（仅契约声明、无运行时断言，最弱层；
///      可执行性由 `run_single` 记 UNKNOWN）。
pub fn evidence_strength(s: &Scenario) -> &'static str {
    if let Some(declared) = s.evidence_strength.as_deref() {
        return match declared {
            "E1" => "E1",
            "E2" => "E2",
            "E3" => "E3",
            "E4" => "E4",
            "E5" => "E5",
            // 非法声明：fail-safe 落到最弱层，绝不静默放大。
            _ => "E1",
        };
    }
    derive_evidence_strength(s)
}

/// 缺省推导（纯函数；显式声明路径见 `evidence_strength`）。
fn derive_evidence_strength(s: &Scenario) -> &'static str {
    if scenario_requires(s) == "real-device" {
        return "E4";
    }
    if !s.fixtures.is_empty() {
        return "E4";
    }
    if s.command.is_some() {
        return "E3";
    }
    // 静态契约：无 [when].command，运行时不可执行（run_single 记 UNKNOWN）。
    "E1"
}

/// TOML 期望值 → JSON 期望值。数组递归转换；标量逐一映射。
///
/// 曾用名 toml_scalar_to_json，对 Array/Datetime/Table 一律返回 Value::Null，
/// 导致数组 equals 期望永远判 FAIL（2026-10-02 workspace-authority-v2 真实踩坑）。
/// toml::Value 的 7 种变体在此全部穷举，不再有静默兜底：未知形状宁可显式
/// 转换失败，也不要悄悄变成 Null（Null 与实际 Null 相等时会误判 PASS）。
fn toml_value_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.iter().map(toml_value_to_json).collect()),
        toml::Value::Table(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_value_to_json(v)))
                .collect(),
        ),
    }
}

/// Load all scenario files under scenarios/<subdir>/.
///
/// 兼容入口：丢弃加载错误（既有调用点签名不变）。需要 fail-closed 判定
/// （场景门 / 索引）的调用方必须用 `load_all_reporting`。
pub fn load_all(scenarios_dir: &Path, subdirs: &[&str]) -> Vec<Scenario> {
    load_all_reporting(scenarios_dir, subdirs).0
}

/// Load scenarios and **return** per-file load errors instead of only logging
/// them. 契约 §4 规则 5 的「不静默丢弃」：调用方据此 fail-closed。
pub fn load_all_reporting(scenarios_dir: &Path, subdirs: &[&str]) -> (Vec<Scenario>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
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
            match load_file(&f, sub) {
                Ok(s) => out.push(s),
                // 契约校验失败的场景不静默丢弃：记录日志 + 回传错误，
                // 由场景门 / 索引 gate 汇总为 FAIL（fail-closed）。
                Err(e) => {
                    let msg = format!("{}: {e}", f.display());
                    eprintln!("[scenario] 跳过 {msg}");
                    errors.push(msg);
                }
            }
        }
    }
    (out, errors)
}

/// 单个 expect 失败的结构化信息（供失败签名使用）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectFailure {
    /// 失败的 expect `field` path。
    pub path: String,
    /// 实际值（JSON 文本；缺失为 "<missing>"）。
    pub actual: String,
}

/// Evaluate a scenario against a command's JSON output.
fn evaluate(scenario: &Scenario, output: &Value) -> Result<(), ExpectFailure> {
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
            // 缺失（None）或显式 null 都算满足；其它一律失败。
            ExpectKind::Absent => matches!(actual, None | Some(Value::Null)),
        };
        if !ok {
            return Err(ExpectFailure {
                path: expect.path.clone(),
                actual: actual
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "<missing>".to_string()),
            });
        }
    }
    Ok(())
}

/// 在 JSON 输出中按 path 查找期望字段。
///
/// 歧义决策（2026-10-02 proxy-fwd 真实踩坑）：example 的机器输出有两种形状——
/// 扁平点分键（如顶层 `"tcp.http_ok": true`）和嵌套对象（如 `{"tcp": {"http_ok": true}}`）。
/// 扁平键本身可含 '.'，只看 path 字符串无法区分两种形状。
/// 规则：**在当前对象上先尝试完整 path 精确匹配，命中则直接返回；否则再按 '.'
/// 切分第一段逐层查找**（对象按段名、数组按数字下标）。扁平键与嵌套路径同名
/// 时，扁平键优先——这是有意为之的确切语义，不是巧合。
fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    match v {
        Value::Object(o) => {
            // 扁平点分键：完整 path 直接命中。
            if let Some(hit) = o.get(path) {
                return Some(hit);
            }
            // 嵌套形状：按 '.' 切分第一段后递归。
            let (head, rest) = path.split_once('.')?;
            get_path(o.get(head)?, rest)
        }
        Value::Array(a) => {
            // 叶子下标：递归到数组时 path 剩余部分可能整体就是数字（如 "a.b.1"）。
            if let Ok(idx) = path.parse::<usize>() {
                return a.get(idx);
            }
            let (head, rest) = path.split_once('.')?;
            let idx = head.parse::<usize>().ok()?;
            get_path(a.get(idx)?, rest)
        }
        _ => None,
    }
}

/// 带退出码的命令执行（E4 夹具用）：返回 `(exit_ok, stdout, stderr_tail)`。
///
/// 语义与 `run_command` 相同（有界执行、stdout/stderr 分开抽干、孤儿进程不
/// 阻塞），区别是透出进程退出码：夹具命令必须 exit 0 才算成功。
fn run_command_checked(
    command: &str,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
    node_dir: Option<&std::path::Path>,
) -> (bool, bool, String, String) {
    let (outcome, stdout, stderr_tail) =
        run_checked_with_timeouts(command, scenario_timeout, drain_timeout, node_dir);
    (
        outcome == RunOutcome::Exited(true),
        outcome == RunOutcome::TimedOut,
        stdout,
        stderr_tail,
    )
}

/// 见 run_command 注释。timeout 参数化仅供回归测试注入短超时。
/// 返回 `(outcome, stdout, stderr_tail)`。
#[derive(Debug, PartialEq, Eq)]
enum RunOutcome {
    /// 进程正常退出；bool = 退出码是否为 0。
    Exited(bool),
    /// 超时被 kill。
    TimedOut,
    /// spawn 失败（命令不存在等）。
    SpawnFailed,
}

fn run_checked_with_timeouts(
    command: &str,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
    node_dir: Option<&std::path::Path>,
) -> (RunOutcome, String, String) {
    let mut parts = command.split_whitespace();
    let program = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();
    let program = if program == "nexus-harness" {
        // 用启动时确立的稳定路径，而不是每次现读 `current_exe()`：运行期
        // `cargo build` 会重链原路径，现读会得到 `(deleted)` 字面量。
        crate::self_exe::stable_self_exe()
            .to_string_lossy()
            .to_string()
    } else {
        program.to_string()
    };
    let mut cmd = Command::new(&program);
    cmd.args(&args);
    // 场景隔离：每个场景用独立的节点目录，fixture 与主命令共享同一目录，
    // 场景之间互不可见。`nexus` 经 `NEXUS_CONFIG_DIR` 读取节点目录
    // （apps/nexus/src/node_cli.rs::node_dir）。
    if let Some(dir) = node_dir {
        cmd.env("NEXUS_CONFIG_DIR", dir);
    }
    run_prepared(cmd, scenario_timeout, drain_timeout, &program)
}

/// 直调产物执行器：与 `run_checked_with_timeouts` 共用 spawn/reader/kill/drain
/// 语义；`current_dir` 为 `None` 时**不调用** `Command::current_dir`，继承
/// harness 自身 CWD（与旧 `cargo run` 路径逐项等价）。
#[allow(clippy::too_many_arguments)]
fn run_resolved(
    program: &std::path::Path,
    args: &[String],
    current_dir: Option<&std::path::Path>,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
    node_dir: Option<&std::path::Path>,
) -> (RunOutcome, String, String) {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = current_dir {
        cmd.current_dir(dir);
    }
    if let Some(dir) = node_dir {
        cmd.env("NEXUS_CONFIG_DIR", dir);
    }
    run_prepared(
        cmd,
        scenario_timeout,
        drain_timeout,
        &program.display().to_string(),
    )
}

fn run_prepared(
    mut cmd: Command,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
    label: &str,
) -> (RunOutcome, String, String) {
    use std::io::Read;
    use std::time::{Duration, Instant};

    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (
                RunOutcome::SpawnFailed,
                String::new(),
                format!("cannot run {label}: {e}"),
            );
        }
    };
    // 读线程：并发抽干 pipe；孤儿进程持有写端时它们可能永不 EOF，
    // 主线程只按 drain_timeout 有限等待，不依赖它们结束。
    let (tx, rx) = std::sync::mpsc::channel::<(bool, Vec<u8>)>();
    if let Some(mut p) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            let _ = tx.send((true, buf));
        });
    }
    if let Some(mut p) = child.stderr.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            let _ = tx.send((false, buf));
        });
    }
    drop(tx);

    let start = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break RunOutcome::Exited(status.success()),
            Ok(None) => {
                if start.elapsed() >= scenario_timeout {
                    let _ = child.kill();
                    // 尽力回收直接子进程；孤儿孙进程由其自行退出，
                    // 不阻塞等待（它们的 pipe 写端已无关大局）。
                    let _ = child.try_wait();
                    break RunOutcome::TimedOut;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break RunOutcome::Exited(false),
        }
    };

    let deadline = Instant::now() + drain_timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for _ in 0..2 {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((true, b)) => stdout = b,
            Ok((false, b)) => stderr = b,
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&stdout).into_owned();
    let err_text = String::from_utf8_lossy(&stderr).into_owned();
    match outcome {
        RunOutcome::TimedOut => (
            RunOutcome::TimedOut,
            text,
            format!(
                "scenario command timed out after {}s: {label}",
                scenario_timeout.as_secs()
            ),
        ),
        _ => {
            let tail: Vec<&str> = err_text.lines().rev().take(8).collect();
            let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
            (outcome, text, tail)
        }
    }
}

/// 旧入口（回归测试用）：保持原语义——spawn 失败/timeout 返回 "false"＋诊断，
/// 正常跑完返回 "true"＋stdout（退出码信息在此丢弃，场景判定只看 JSON）。
#[allow(dead_code)]
fn run_command_with_timeouts(
    command: &str,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
    node_dir: Option<&std::path::Path>,
) -> (String, String) {
    let (outcome, stdout, stderr_tail) =
        run_checked_with_timeouts(command, scenario_timeout, drain_timeout, node_dir);
    match outcome {
        RunOutcome::Exited(_) => (true.to_string(), stdout),
        // timeout / spawn 失败：诊断文本在 stderr_tail（与旧实现一致）。
        _ => (false.to_string(), stderr_tail),
    }
}

/// 单场景执行的结构化报告（机器接口 `scenario run` 的失败签名来源）。
///
/// verdict 取值：PASS | FAIL | UNKNOWN | BLOCKED。
/// - UNKNOWN：平台不匹配 / 静态契约无 `[when].command` / n3 contract-first 未实现。
///   `scenario run` 机器接口把 UNKNOWN 映射为 BLOCKED；
///   run_gate 保持原有的 UNKNOWN 记录语义（不阻塞门禁）。
pub struct ScenarioRunReport {
    pub verdict: String,
    /// 失败步骤："" | "fixture" | "command" | "expect" | "parse" | "lookup"。
    pub failed_step: String,
    /// 失败断言：fixture 命令原文 / "spawn_failed" / "timed_out" /
    /// expect field path / ""（parse、lookup、平台不匹配时为说明文本）。
    pub assertion: String,
    /// 最近 10 行相关日志（PASS 时为空数组）。
    pub key_log_lines: Vec<String>,
    /// 单场景墙钟毫秒数（含 fixture）。
    pub duration_ms: u64,
    /// 主命令或 fixture 是否因 tier 超时被 kill。
    pub timed_out: bool,
    /// 人类可读明细（与旧 ScenarioResult.detail 同格式）。
    pub detail: String,
    /// 命令成功解析后的 JSON 输出（证据可追溯；失败为 None）。
    pub output: Option<Value>,
}

/// 取文本最后至多 n 行。
fn tail_lines(text: &str, n: usize) -> Vec<String> {
    text.lines()
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(str::to_string)
        .collect()
}

fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "other"
    }
}

/// 执行单个场景。执行语义与旧 run_gate 逐场景循环完全一致
/// （fixture 顺序执行、有界超时、场景级 NEXUS_CONFIG_DIR 隔离、
/// n3 contract-first 的 UNKNOWN 特例），只是把失败信息结构化。
pub fn run_single(
    s: &Scenario,
    artifacts: Option<&ScenarioArtifacts>,
    timeouts: &ScenarioTimeouts,
) -> ScenarioRunReport {
    use std::time::Instant;
    let start = Instant::now();
    let mut rep = run_single_inner(s, artifacts, timeouts);
    rep.duration_ms = start.elapsed().as_millis() as u64;
    rep
}

fn unknown_report(failed_step: &str, assertion: String, detail: String) -> ScenarioRunReport {
    ScenarioRunReport {
        verdict: "UNKNOWN".to_string(),
        failed_step: failed_step.to_string(),
        assertion,
        key_log_lines: Vec::new(),
        duration_ms: 0,
        timed_out: false,
        output: None,
        detail,
    }
}

fn run_single_inner(
    s: &Scenario,
    artifacts: Option<&ScenarioArtifacts>,
    timeouts: &ScenarioTimeouts,
) -> ScenarioRunReport {
    // 平台门：与旧 run_gate 语义一致（不匹配记 UNKNOWN，不阻塞）。
    if let Some(plat) = &s.platform {
        let current_plat = current_platform();
        if plat != current_plat {
            let detail = format!("platform contract ({plat} required, host is {current_plat})");
            return unknown_report("lookup", detail.clone(), detail);
        }
    }
    let cmd = match &s.command {
        None => {
            return unknown_report(
                "lookup",
                String::new(),
                "static contract, runtime not exercisable by harness (no [when].command)"
                    .to_string(),
            );
        }
        Some(c) => c.clone(),
    };
    // 场景隔离：每个场景独占一个节点目录（`NEXUS_CONFIG_DIR`），
    // fixture 与主命令共享同一目录、场景之间互不可见。否则多个
    // N2 场景共用默认目录、`dev-svc` 等同名资源互相污染
    // （如 n2-resource-revoke 的撤销影响 n2-use-loop）。
    let scenario_node_dir = std::env::temp_dir().join(format!(
        "nexus-scenario-{}-{}",
        s.id.replace(['/', '\\'], "_"),
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&scenario_node_dir);
    let node_dir = Some(scenario_node_dir.as_path());
    // E4 夹具（P0-6）：先按序跑 `[given].fixture`，全部 exit 0 才跑
    // 场景命令；任一夹具失败 → 场景 FAIL（夹具是 E4 环境声明）。
    let scenario_timeout = timeouts.for_scenario(s);
    for fixture in &s.fixtures {
        let resolved = artifacts.map(|a| resolve_scenario_command(fixture, a));
        let (ok, timed_out, _out, err_tail) = match resolved {
            Some(ResolvedCommand::Unavailable { reason }) => {
                return ScenarioRunReport {
                    verdict: "FAIL".to_string(),
                    failed_step: "fixture".to_string(),
                    assertion: reason.lines().next().unwrap_or_default().to_string(),
                    key_log_lines: tail_lines(&reason, 10),
                    duration_ms: 0,
                    timed_out: false,
                    output: None,
                    detail: reason,
                };
            }
            Some(ResolvedCommand::MissingTarget {
                package,
                kind,
                target,
            }) => {
                let assertion = format!("{package}:{kind}:{target}");
                return ScenarioRunReport {
                    verdict: "FAIL".to_string(),
                    failed_step: "fixture".to_string(),
                    key_log_lines: Vec::new(),
                    assertion: assertion.clone(),
                    duration_ms: 0,
                    timed_out: false,
                    output: None,
                    detail: format!("fixture target not declared: {assertion}"),
                };
            }
            Some(ResolvedCommand::Direct {
                program,
                args,
                current_dir,
            }) => {
                let (outcome, out, err) = run_resolved(
                    &program,
                    &args,
                    current_dir.as_deref(),
                    scenario_timeout,
                    timeouts.drain,
                    node_dir,
                );
                (
                    outcome == RunOutcome::Exited(true),
                    outcome == RunOutcome::TimedOut,
                    out,
                    err,
                )
            }
            Some(ResolvedCommand::Unchanged { command }) => {
                run_command_checked(&command, scenario_timeout, timeouts.drain, node_dir)
            }
            None => run_command_checked(fixture, scenario_timeout, timeouts.drain, node_dir),
        };
        if timed_out {
            return ScenarioRunReport {
                verdict: "FAIL".to_string(),
                failed_step: "fixture".to_string(),
                assertion: "timed_out".to_string(),
                key_log_lines: tail_lines(&err_tail, 10),
                duration_ms: 0,
                timed_out: true,
                output: None,
                detail: format!(
                    "fixture command timed out after {}s: {fixture}",
                    scenario_timeout.as_secs()
                ),
            };
        }
        if !ok {
            return ScenarioRunReport {
                verdict: "FAIL".to_string(),
                failed_step: "fixture".to_string(),
                assertion: fixture.clone(),
                key_log_lines: tail_lines(&err_tail, 10),
                duration_ms: 0,
                timed_out: false,
                output: None,
                detail: format!("fixture failed: {fixture} (stderr: {err_tail})"),
            };
        }
    }
    // 主命令：有界执行，透出 RunOutcome 以区分"命令失败"与"输出解析失败"。
    // artifacts=Some 时先解析为直调产物；不可用即 FAIL（fail-closed，不静默跳过）。
    let resolved = artifacts.map(|a| resolve_scenario_command(&cmd, a));
    let (outcome, stdout, stderr_tail) = match resolved {
        Some(ResolvedCommand::MissingTarget {
            package,
            kind,
            target,
        }) => {
            let assertion = format!("{package}:{kind}:{target}");
            // contract-first：基线里 `cargo run` 找不到该 target，stdout 为空，
            // 场景被记为 UNKNOWN（master 既有 Red）。缺失 target 不是预编失败，
            // 保持同一语义且不再 spawn cargo。
            if s.id.starts_with("product.n3-") {
                return unknown_report(
                    "parse",
                    String::new(),
                    "contract-first: n3_task_e4 not implemented (master Red)".to_string(),
                );
            }
            return ScenarioRunReport {
                verdict: "FAIL".to_string(),
                failed_step: "prebuild".to_string(),
                key_log_lines: Vec::new(),
                assertion,
                duration_ms: 0,
                timed_out: false,
                output: None,
                detail: format!("target not declared: {package}:{kind}:{target}"),
            };
        }
        Some(ResolvedCommand::Unavailable { reason }) => {
            return ScenarioRunReport {
                verdict: "FAIL".to_string(),
                failed_step: "prebuild".to_string(),
                assertion: reason.lines().next().unwrap_or_default().to_string(),
                key_log_lines: tail_lines(&reason, 10),
                duration_ms: 0,
                timed_out: false,
                output: None,
                detail: reason,
            };
        }
        Some(ResolvedCommand::Direct {
            program,
            args,
            current_dir,
        }) => run_resolved(
            &program,
            &args,
            current_dir.as_deref(),
            scenario_timeout,
            timeouts.drain,
            node_dir,
        ),
        _ => run_checked_with_timeouts(&cmd, scenario_timeout, timeouts.drain, node_dir),
    };
    match outcome {
        RunOutcome::TimedOut => ScenarioRunReport {
            verdict: "FAIL".to_string(),
            failed_step: "command".to_string(),
            assertion: "timed_out".to_string(),
            key_log_lines: tail_lines(&format!("{stdout}\n{stderr_tail}"), 10),
            duration_ms: 0,
            timed_out: true,
            output: None,
            detail: format!(
                "scenario command timed out after {}s",
                scenario_timeout.as_secs()
            ),
        },
        RunOutcome::SpawnFailed => ScenarioRunReport {
            verdict: "FAIL".to_string(),
            failed_step: "command".to_string(),
            assertion: "spawn_failed".to_string(),
            key_log_lines: tail_lines(&stderr_tail, 10),
            duration_ms: 0,
            timed_out: false,
            output: None,
            detail: format!("cannot run scenario command: {stderr_tail}"),
        },
        RunOutcome::Exited(_) => match serde_json::from_str::<Value>(&stdout) {
            Ok(json) => match evaluate(s, &json) {
                Ok(()) => ScenarioRunReport {
                    verdict: "PASS".to_string(),
                    failed_step: String::new(),
                    assertion: String::new(),
                    key_log_lines: Vec::new(),
                    duration_ms: 0,
                    timed_out: false,
                    output: Some(json),
                    detail: format!("command ran, all {} expectations held", s.expects.len()),
                },
                Err(f) => ScenarioRunReport {
                    verdict: "FAIL".to_string(),
                    failed_step: "expect".to_string(),
                    assertion: f.path.clone(),
                    key_log_lines: tail_lines(&stdout, 10),
                    duration_ms: 0,
                    timed_out: false,
                    output: None,
                    detail: format!("expect {}.{} failed (actual: {})", s.id, f.path, f.actual),
                },
            },
            Err(e) => {
                // N3 contract-first: n3_task_e4 example 从未交付（master 既有 Red，
                // 非 P1 回归）。输出为空时标记为 UNKNOWN 而非 FAIL，避免门禁被
                // 未实现的契约阻塞；冻结的 TOML 期望未动。
                let is_n3_contract_first =
                    s.id.starts_with("product.n3-") && stdout.trim().is_empty();
                if is_n3_contract_first {
                    unknown_report(
                        "parse",
                        String::new(),
                        "contract-first: n3_task_e4 not implemented (master Red)".to_string(),
                    )
                } else {
                    ScenarioRunReport {
                        verdict: "FAIL".to_string(),
                        failed_step: "parse".to_string(),
                        assertion: String::new(),
                        key_log_lines: tail_lines(&stdout, 10),
                        duration_ms: 0,
                        timed_out: false,
                        output: None,
                        detail: format!("output not JSON ({e}): {}", stdout.trim()),
                    }
                }
            }
        },
    }
}

/// 场景并行度：环境变量 NEXUS_HARNESS_JOBS 优先（1 表示强制串行，
/// 兼容旧行为）；否则按 CPU 数，上限 16。场景主体是等待子进程，
/// I/O 密集，允许超配；上限防止大机器上进程爆炸。
fn parallel_jobs() -> usize {
    parallel_jobs_from_env(std::env::var("NEXUS_HARNESS_JOBS").ok())
}

fn parallel_jobs_from_env(v: Option<String>) -> usize {
    if let Some(s) = v {
        if let Ok(n) = s.trim().parse::<usize>() {
            return n.max(1);
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16)
}

/// 有界并行执行场景：worker 线程从共享队列认领下标，结果经 channel
/// 按下标回填。`Scenario` 是纯数据（Send+Sync），`run_single` 内只有
/// 进程隔离的副作用（独立目录/端口），无跨场景共享可变状态。
/// 任一 worker panic 时 scope 会传播 panic（与串行版行为一致：整轮中止）。
fn run_parallel(
    scenarios: &[Scenario],
    jobs: usize,
    artifacts: Option<&ScenarioArtifacts>,
    timeouts: &ScenarioTimeouts,
) -> Vec<ScenarioRunReport> {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, mpsc};

    let n = scenarios.len();
    let workers = jobs.min(n);
    let queue: Arc<Mutex<VecDeque<usize>>> = Arc::new(Mutex::new((0..n).collect()));
    let (tx, rx) = mpsc::channel::<(usize, ScenarioRunReport)>();

    std::thread::scope(|s| {
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            s.spawn(move || {
                loop {
                    // 锁只保护取下标；子进程执行期间不持锁。
                    let idx = match queue.lock().unwrap().pop_front() {
                        Some(i) => i,
                        None => break,
                    };
                    let rep = run_single(&scenarios[idx], artifacts, timeouts);
                    // 主线程一定在收（rx 在 scope 内消费），send 不会阻塞。
                    let _ = tx.send((idx, rep));
                }
            });
        }
        drop(tx);

        let mut by_idx: Vec<Option<ScenarioRunReport>> = (0..n).map(|_| None).collect();
        for (idx, rep) in rx {
            by_idx[idx] = Some(rep);
        }
        by_idx
            .into_iter()
            .enumerate()
            .map(|(i, slot)| {
                slot.unwrap_or_else(|| ScenarioRunReport {
                    verdict: "FAIL".to_string(),
                    failed_step: "harness".to_string(),
                    assertion: String::new(),
                    key_log_lines: Vec::new(),
                    duration_ms: 0,
                    timed_out: false,
                    output: None,
                    detail: format!(
                        "scenario worker produced no report for '{}' (worker panic?)",
                        scenarios[i].id
                    ),
                })
            })
            .collect()
    })
}

/// Run all command-scenarios in the given subdirs; static ones are recorded
/// UNKNOWN. Returns (results, gate) — gate is FAIL if any scenario FAIL.
///
/// 逐场景执行委托给 run_single（单一执行路径）；本函数只做聚合与 Gate 判定。
/// 场景之间并行执行：每个场景是独立子进程（独立 NEXUS_CONFIG_DIR、临时端口），
/// 无共享可变状态；结果按场景声明顺序收集，保证输出确定性。
pub fn run_gate(
    config: &Config,
    gate_name: &str,
    subdirs: &[&str],
    artifacts: Option<&ScenarioArtifacts>,
    timeouts: &ScenarioTimeouts,
) -> (Vec<ScenarioResult>, Gate) {
    use std::time::Instant;
    let started = Instant::now();
    let (scenarios, load_errors) = load_all_reporting(&config.scenarios_dir, subdirs);
    // fail-closed：任何场景加载失败都先于「空集早退」判 FAIL。否则
    // carrier 写错/漏写的场景会从集合里消失而 gate 仍可能 PASS
    // （AC-13 机械不可判定）。
    if !load_errors.is_empty() {
        let detail = format!(
            "{} scenario file(s) failed to load:\n{}",
            load_errors.len(),
            load_errors.join("\n")
        );
        let mut gate = Gate::fail(gate_name, &detail);
        gate.duration_ms = started.elapsed().as_millis() as u64;
        return (Vec::new(), gate);
    }
    if scenarios.is_empty() {
        return (
            Vec::new(),
            Gate::ok(gate_name, "no scenario files declared"),
        );
    }
    let jobs = parallel_jobs();
    let reports: Vec<ScenarioRunReport> = if jobs <= 1 || scenarios.len() <= 1 {
        scenarios
            .iter()
            .map(|s| run_single(s, artifacts, timeouts))
            .collect()
    } else {
        run_parallel(&scenarios, jobs, artifacts, timeouts)
    };
    let mut results: Vec<ScenarioResult> = Vec::new();
    let mut failed = false;
    // reports 在此之后不再使用，直接 move 字段，省去堆内存复制（review suggestion）。
    for (s, rep) in scenarios.iter().zip(reports) {
        if rep.verdict == "FAIL" {
            failed = true;
        }
        results.push(ScenarioResult {
            id: s.id.clone(),
            carrier: s.carrier,
            verdict: rep.verdict,
            detail: rep.detail,
            duration_ms: rep.duration_ms,
            timed_out: rep.timed_out,
        });
    }
    // 契约 §3：Gate detail 逐场景带上真机/sandbox 分层（requires）与证据
    // 分层（evidence=E1–E5），报告层据此按强度聚合，而不是只看到 verdict。
    let detail: Vec<String> = scenarios
        .iter()
        .zip(results.iter())
        .map(|(s, r)| {
            format!(
                "{}: {} (requires={}, evidence={}, carrier={}; {})",
                r.id,
                r.verdict,
                scenario_requires(s),
                evidence_strength(s),
                r.carrier.as_str(),
                r.detail
            )
        })
        .collect();
    let detail = detail.join("\n");
    let mut gate = if failed {
        Gate::fail(gate_name, &detail)
    } else {
        Gate::ok(gate_name, &detail)
    };
    gate.duration_ms = started.elapsed().as_millis() as u64;
    (results, gate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scenario(expects: Vec<ScenarioExpect>) -> Scenario {
        Scenario {
            id: "t".to_string(),
            subdir: "product".to_string(),
            title: "test".to_string(),
            requires_root: false,
            file_stem: "t".to_string(),
            platform: None,
            fixtures: Vec::new(),
            command: None,
            expects,
            evidence_strength: None,
            carrier: Carrier::Engineering,
        }
    }

    #[test]
    fn get_path_nested_and_array() {
        let v = json!({"a": {"b": [10, 20]}});
        assert_eq!(get_path(&v, "a.b.1"), Some(&json!(20)));
        assert_eq!(get_path(&v, "a.b.2"), None);
        assert_eq!(get_path(&v, "missing"), None);
    }

    /// 回归：example 输出扁平点分键（proxy-fwd 的 "tcp.http_ok"）时，
    /// 完整键精确匹配必须命中，不能报 <missing>。
    #[test]
    fn get_path_flat_dotted_key() {
        let v = json!({"tcp.http_ok": true, "verdict": "PASS"});
        assert_eq!(get_path(&v, "tcp.http_ok"), Some(&json!(true)));
        assert_eq!(get_path(&v, "verdict"), Some(&json!("PASS")));
        assert_eq!(get_path(&v, "tcp.missing"), None);
    }

    /// 嵌套形状保持原有语义：逐层查找仍然可用。
    #[test]
    fn get_path_nested_still_works() {
        let v = json!({"tcp": {"http_ok": true}});
        assert_eq!(get_path(&v, "tcp.http_ok"), Some(&json!(true)));
        assert_eq!(get_path(&v, "tcp"), Some(&json!({"http_ok": true})));
    }

    /// 歧义优先级：扁平键与嵌套路径同名时，扁平键精确匹配优先。
    #[test]
    fn get_path_flat_key_wins_over_nested() {
        let v = json!({"a.b": 1, "a": {"b": 2}});
        assert_eq!(get_path(&v, "a.b"), Some(&json!(1)));
    }

    /// 数组下标在递归末端：单段数字 path 在数组上直接按下标取。
    #[test]
    fn get_path_array_leaf_index() {
        let v = json!({"items": ["x", "y"]});
        assert_eq!(get_path(&v, "items.0"), Some(&json!("x")));
        assert_eq!(get_path(&v, "items.1"), Some(&json!("y")));
        assert_eq!(get_path(&v, "items.2"), None);
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

    /// 回归：TOML 无 null 字面量，`equals = null` 曾让 node_priority /
    /// traffic_stats 两个场景文件整体解析失败被静默跳过（2026-10-18 审计发现）。
    /// `absent = true` 必须同时接受「字段缺失」与「显式 JSON null」，
    /// 且不得接受任何其它值。
    #[test]
    fn evaluate_absent_accepts_missing_and_null_only() {
        let s = scenario(vec![ScenarioExpect {
            path: "empty_candidates.selected_node_id".to_string(),
            kind: ExpectKind::Absent,
        }]);
        // 字段缺失 → 满足
        assert!(evaluate(&s, &json!({"empty_candidates": {}})).is_ok());
        // 显式 null → 满足
        assert!(evaluate(&s, &json!({"empty_candidates": {"selected_node_id": null}})).is_ok());
        // 整条父路径缺失 → 满足
        assert!(evaluate(&s, &json!({})).is_ok());
        // 有值 → 失败，且失败签名带上实际值便于取证
        let err = evaluate(
            &s,
            &json!({"empty_candidates": {"selected_node_id": "node-1"}}),
        )
        .unwrap_err();
        assert_eq!(err.path, "empty_candidates.selected_node_id");
        assert_eq!(err.actual, "\"node-1\"");
        // 空串 / 0 都不算 absent
        assert!(evaluate(&s, &json!({"empty_candidates": {"selected_node_id": ""}})).is_err());
    }

    /// 回归：`absent = true` 的 TOML 形态必须能被 load_file 解析出来
    ///（否则与 `equals = null` 一样是静默跳过）。
    #[test]
    fn load_parses_absent_expect() {
        let dir = std::env::temp_dir().join(format!("harness-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.absent\"\ncarrier = \"engineering\"\n[when]\ncommand = \"{}\"\n[[expect]]\nfield = \"a.b\"\nabsent = true\n",
        )
        .expect("write toml");
        let loaded = load_file(&dir.join("s.toml"), "product").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded.expects.len(), 1);
        assert_eq!(loaded.expects[0].path, "a.b");
        assert!(matches!(loaded.expects[0].kind, ExpectKind::Absent));
    }

    /// 回归：数组 equals 期望必须按数组比较，不能静默变成 Null 永远判 FAIL
    ///（2026-10-02 workspace-authority-v2 的 conflict.paths 真实踩坑）。
    #[test]
    fn evaluate_array_equals() {
        let toml_expect: toml::Value = toml::from_str(r#"equals = ["conflict.txt"]"#)
            .map(|v: toml::Value| v["equals"].clone())
            .unwrap();
        let expected = toml_value_to_json(&toml_expect);
        assert_eq!(expected, json!(["conflict.txt"]));
        let s = scenario(vec![ScenarioExpect {
            path: "conflict.paths".to_string(),
            kind: ExpectKind::Equals(expected),
        }]);
        assert!(evaluate(&s, &json!({"conflict": {"paths": ["conflict.txt"]}})).is_ok());
        assert!(evaluate(&s, &json!({"conflict": {"paths": ["other.txt"]}})).is_err());
        assert!(evaluate(&s, &json!({"conflict": {}})).is_err());
    }

    #[test]
    fn toml_value_to_json_covers_all_shapes() {
        // 标量
        assert_eq!(
            toml_value_to_json(&toml::Value::String("a".into())),
            json!("a")
        );
        assert_eq!(toml_value_to_json(&toml::Value::Integer(3)), json!(3));
        assert_eq!(toml_value_to_json(&toml::Value::Float(1.5)), json!(1.5));
        assert_eq!(toml_value_to_json(&toml::Value::Boolean(true)), json!(true));
        // 嵌套数组递归转换
        let arr: toml::Value = toml::from_str(r#"x = [1, ["a", "b"], 2.5]"#)
            .map(|v: toml::Value| v["x"].clone())
            .unwrap();
        assert_eq!(toml_value_to_json(&arr), json!([1, ["a", "b"], 2.5]));
        // table 递归成 object
        let tbl: toml::Value = toml::from_str("[x]\ny = 1\n")
            .map(|v: toml::Value| v["x"].clone())
            .unwrap();
        assert_eq!(toml_value_to_json(&tbl), json!({"y": 1}));
    }

    /// 回归：stderr 的人类可读日志不得污染场景 JSON 判定。
    /// 2026-10-02 full verify 误判：composition-root / workspace-sync-authz 的
    /// eprintln! 日志被拼进判定文本导致 "output not JSON"。产品侧本就正确
    /// （日志走 stderr），修的是 harness：只按 stdout 做 JSON 判定。
    #[test]
    fn run_command_ignores_stderr_for_scenario_json() {
        use std::time::Duration;
        // run_command 按空白切分命令，不支持 shell 引号；用临时脚本文件。
        let dir = std::env::temp_dir().join(format!("harness-stderr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let script = dir.join("emit.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho '{\"verdict\":\"PASS\"}'\necho '[nexusd] human log' >&2\n",
        )
        .expect("write script");
        let (ok, out) = run_command_with_timeouts(
            &format!("sh {}", script.to_str().expect("utf8 path")),
            Duration::from_secs(10),
            Duration::from_secs(5),
            None,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(ok, "true");
        assert_eq!(out.trim(), "{\"verdict\":\"PASS\"}");
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    /// 回归：直接子进程超时必须有界返回，不能永挂。
    #[test]
    fn run_command_times_out_instead_of_hanging() {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let (ok, out) = run_command_with_timeouts(
            "sleep 30",
            Duration::from_secs(2),
            Duration::from_secs(1),
            None,
        );
        assert_eq!(ok, "false");
        assert!(out.contains("timed out"), "unexpected: {out}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "run_command hung: {:?}",
            start.elapsed()
        );
    }

    /// 回归：直接子进程已退出、但孤儿孙进程持有 pipe 写端时，
    /// 不能阻塞等 EOF，必须有界返回（2026-10-02 n1_roam 真实踩坑）。
    #[test]
    fn run_command_orphaned_grandchild_holding_pipe_returns() {
        use std::time::{Duration, Instant};
        // sh 立刻退出，sleep 60（孙进程）继承 stdout pipe 写端且不写任何东西。
        // 旧实现（Command::output）会在此卡满 60 秒等 EOF。
        let start = Instant::now();
        let (ok, _) = run_command_with_timeouts(
            "sh -c 'sleep 60 &'",
            Duration::from_secs(120),
            Duration::from_secs(2),
            None,
        );
        let elapsed = start.elapsed();
        assert_eq!(ok, "true");
        assert!(
            elapsed < Duration::from_secs(15),
            "run_command hung on orphaned pipe holder: {elapsed:?}"
        );
    }

    /// 契约 §2 / §4.5：`schema_version` 缺省或非 1 时 `load_file` 返回 Err，
    /// `load_all` 跳过该场景（不 panic、不静默入库）。
    ///
    /// 覆盖 82cc534 引入的拒绝分支：此前该字段根本不校验，异构/旧版场景
    /// 会被当合法场景加载，expect 与实现脱钩也无法察觉。
    #[test]
    fn load_rejects_invalid_schema_version() {
        for (label, toml) in [
            ("absent", "id = \"t.nover\"\n[when]\ncommand = \"true\"\n"),
            (
                "wrong",
                "schema_version = 2\nid = \"t.v2\"\n[when]\ncommand = \"true\"\n",
            ),
            (
                "non_integer",
                "schema_version = \"1\"\nid = \"t.str\"\n[when]\ncommand = \"true\"\n",
            ),
        ] {
            let dir =
                std::env::temp_dir().join(format!("harness-sv-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("tmpdir");
            std::fs::write(dir.join("s.toml"), toml).expect("write toml");
            let scenarios = load_all(&dir, &[""]);
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                scenarios.is_empty(),
                "schema_version {label} 必须被拒绝，实际加载了 {} 个场景",
                scenarios.len()
            );
        }
    }

    /// 契约 §2：`schema_version = 1` 是合法值，不得被上面的规则误伤。
    #[test]
    fn load_accepts_schema_version_one() {
        let dir = std::env::temp_dir().join(format!("harness-sv1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.v1\"\ncarrier = \"engineering\"\n[when]\ncommand = \"true\"\n",
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].id, "t.v1");
    }

    /// E4 夹具（P0-6）：`[given].fixture` 字符串数组被解析进 Scenario。
    #[test]
    fn fixture_parsed_from_given() {
        let dir = std::env::temp_dir().join(format!("harness-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.fixture\"\ncarrier = \"engineering\"\n[given]\nfixture = [\"echo one\", \"echo two\"]\n[when]\ncommand = \"echo hi\"\n",
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(
            scenarios[0].fixtures,
            vec!["echo one".to_string(), "echo two".to_string()]
        );
    }

    /// E4 夹具（P0-6）：无 fixture 声明 → 空 vec（旧场景不受影响）。
    #[test]
    fn fixture_absent_is_empty() {
        let dir = std::env::temp_dir().join(format!("harness-nofixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.nofixture\"\ncarrier = \"engineering\"\n[given]\n[when]\ncommand = \"echo hi\"\n",
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert!(scenarios[0].fixtures.is_empty());
    }

    /// E4 夹具（P0-6）：run_command_checked 透出退出码（夹具成败判据）。
    #[test]
    fn run_command_checked_reports_exit_status() {
        let timeout = std::time::Duration::from_secs(10);
        let drain = std::time::Duration::from_secs(1);
        let (ok, _, _, _) = run_command_checked("true", timeout, drain, None);
        assert!(ok, "exit 0 must be ok");
        let (ok, _, _, err) = run_command_checked("false", timeout, drain, None);
        assert!(!ok, "exit 1 must not be ok: {err}");
        let (ok, _, _, err) =
            run_command_checked("definitely-not-a-real-command-xyz", timeout, drain, None);
        assert!(!ok, "spawn failure must not be ok: {err}");
    }

    /// E4 夹具（P0-6）：非字符串 fixture 条目被忽略（不炸解析）。
    #[test]
    fn fixture_non_string_entries_ignored() {
        let dir = std::env::temp_dir().join(format!("harness-fixture2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.fixture2\"\ncarrier = \"engineering\"\n[given]\nfixture = [\"echo ok\", 42]\n[when]\ncommand = \"echo hi\"\n",
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].fixtures, vec!["echo ok".to_string()]);
    }

    /// 场景包：evaluate 返回结构化失败（path + actual），供失败签名使用。
    #[test]
    fn evaluate_structured_failure() {
        let s = scenario(vec![ScenarioExpect {
            path: "up.up_ok".to_string(),
            kind: ExpectKind::Equals(json!(true)),
        }]);
        let err = evaluate(&s, &json!({"up": {"up_ok": false}})).expect_err("must fail");
        assert_eq!(err.path, "up.up_ok");
        assert_eq!(err.actual, "false");
        let err = evaluate(&s, &json!({})).expect_err("must fail");
        assert_eq!(err.path, "up.up_ok");
        assert_eq!(err.actual, "<missing>");
    }

    /// 场景包：requires 启发式 v1（CONTRACT-scenario-pack.md 冻结规则）。
    #[test]
    fn scenario_requires_heuristic() {
        let mut s = scenario(vec![]);
        // 默认 → sandbox。
        assert_eq!(scenario_requires(&s), "sandbox");
        // requires_root = true → real-device。
        s.requires_root = true;
        assert_eq!(scenario_requires(&s), "real-device");
        s.requires_root = false;
        // 文件 stem 含 realnet → real-device。
        s.file_stem = "n1_connectivity_roam_realnet".to_string();
        assert_eq!(scenario_requires(&s), "real-device");
        // id 含 realnet → real-device（大小写不敏感）。
        s.file_stem = "x".to_string();
        s.id = "product.n1-connectivity-roam-realnet".to_string();
        assert_eq!(scenario_requires(&s), "real-device");
        // id 含 real_net → real-device（评审 WARN：此前实现漏查 id 的 real_net）。
        s.id = "product.n1-connectivity-roam-real_net".to_string();
        assert_eq!(scenario_requires(&s), "real-device");
    }

    /// 证据分层（契约 §3）：显式声明 E1–E5 原样返回。
    #[test]
    fn evidence_strength_explicit_declaration() {
        for declared in ["E1", "E2", "E3", "E4", "E5"] {
            let mut s = scenario(vec![]);
            s.evidence_strength = Some(declared.to_string());
            assert_eq!(evidence_strength(&s), declared);
        }
    }

    /// 证据分层推导（契约 §3 与 scenario_requires 的显式关联）：
    /// real-device → E4；fixture → E4；command → E3；静态契约 → E1。
    #[test]
    fn evidence_strength_derived_when_absent() {
        let mut s = scenario(vec![]);
        s.evidence_strength = None;
        // 沙箱 + 有命令 → E3（harness verify 的 product-scenarios gate 执行）。
        s.command = Some("echo hi".to_string());
        assert_eq!(evidence_strength(&s), "E3");
        // 带 E4 夹具 → E4（契约 §3："scenario + fixture，离线可复现"）。
        s.fixtures = vec!["true".to_string()];
        assert_eq!(evidence_strength(&s), "E4");
        s.fixtures = Vec::new();
        // real-device（requires_root）→ E4（真机/隔离环境）。
        s.requires_root = true;
        assert_eq!(evidence_strength(&s), "E4");
        s.requires_root = false;
        // 静态契约（无 [when].command）→ E1（仅契约声明，最弱层）。
        s.command = None;
        assert_eq!(evidence_strength(&s), "E1");
    }

    /// 证据分层非法值 fail-safe：拼错/异构声明降级 E1，不得获得比推导
    /// 更强的强度（与 load_file 拒绝 schema_version != 1 同哲学）。
    #[test]
    fn evidence_strength_invalid_value_fails_safe_to_e1() {
        let mut s = scenario(vec![]);
        s.command = Some("echo hi".to_string());
        for bad in ["E9", "e3", "E", "E44", "STRONG", ""] {
            s.evidence_strength = Some(bad.to_string());
            assert_eq!(
                evidence_strength(&s),
                "E1",
                "invalid declaration {bad:?} must fail safe to E1"
            );
        }
    }

    /// 证据分层从 toml 解析（契约 §2 的 evidence_strength 字段）。
    #[test]
    fn evidence_strength_parsed_from_toml() {
        let (dir, scenarios) = synthetic_scenario(
            "ev",
            "schema_version = 1\nid = \"t.ev\"\nevidence_strength = \"E4\"\ncarrier = \"engineering\"\n[given]\nfixture = [\"true\"]\n[when]\ncommand = \"echo {\\\"verdict\\\":\\\"PASS\\\"}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].evidence_strength.as_deref(), Some("E4"));
        assert_eq!(evidence_strength(&scenarios[0]), "E4");
        // fixture 场景若未显式声明也会推导到 E4；此处显式优先。
        assert_eq!(scenario_requires(&scenarios[0]), "sandbox");
    }

    /// run_gate 的 Gate detail 必须带每个场景的 requires + evidence_strength
    /// （契约 §3：报告层按分层聚合，而不是只看到 verdict）。
    #[test]
    fn run_gate_detail_includes_requires_and_evidence() {
        let dir = std::env::temp_dir().join(format!("harness-gate-detail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        // 命令经 sh 脚本产出 JSON（裸 echo 在 Windows 的 MSYS2 echo.exe 下
        // 会丢参数只输出空行；sh 在 Linux 与 Git Bash 下均可用）。
        let script = dir.join("emit.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' '{\"verdict\":\"PASS\"}'\n",
        )
        .expect("write script");
        let cmd = format!("sh {}", script.display());
        // 场景 A：沙箱 + 命令 → E3。
        std::fs::write(
            dir.join("a.toml"),
            format!(
                "schema_version = 1\nid = \"t.a\"\ncarrier = \"external\"\n[when]\ncommand = \"{}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
                toml_escape(&cmd)
            ),
        )
        .expect("write a.toml");
        // 场景 B：real-device + 命令 → E4。
        std::fs::write(
            dir.join("b.toml"),
            format!(
                "schema_version = 1\nid = \"t.b\"\nrequires_root = true\ncarrier = \"external\"\n[when]\ncommand = \"{}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
                toml_escape(&cmd)
            ),
        )
        .expect("write b.toml");
        let config = Config {
            policies_dir: dir.join("policies"),
            scenarios_dir: dir.clone(),
            evidence_dir: dir.join("evidence"),
            crates_dir: dir.join("crates"),
            engineering_dir: dir.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        let (results, gate) = run_gate(
            &config,
            "product-scenarios",
            &[""],
            None,
            &ScenarioTimeouts::legacy(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(results.len(), 2);
        assert_eq!(gate.verdict, "PASS", "{}", gate.detail);
        assert!(gate.detail.contains("t.a: PASS"), "{}", gate.detail);
        assert!(gate.detail.contains("requires=sandbox"), "{}", gate.detail);
        assert!(gate.detail.contains("evidence=E3"), "{}", gate.detail);
        assert!(gate.detail.contains("t.b: PASS"), "{}", gate.detail);
        assert!(
            gate.detail.contains("requires=real-device"),
            "{}",
            gate.detail
        );
        assert!(gate.detail.contains("evidence=E4"), "{}", gate.detail);
    }

    /// 场景包：title / subdir / requires_root 从 toml 解析。
    #[test]
    fn scenario_meta_parsed_from_toml() {
        let dir = std::env::temp_dir().join(format!("harness-meta-{}", std::process::id()));
        let sub = dir.join("product");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sub).expect("tmpdir");
        std::fs::write(
            sub.join("m.toml"),
            "schema_version = 1\nid = \"t.meta\"\ntitle = \"元信息测试\"\nrequires_root = true\ncarrier = \"engineering\"\n[when]\ncommand = \"echo hi\"\n",
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &["product"]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].title, "元信息测试");
        assert_eq!(scenarios[0].subdir, "product");
        assert!(scenarios[0].requires_root);
        assert_eq!(scenarios[0].file_stem, "m");
        assert_eq!(scenario_requires(&scenarios[0]), "real-device");
    }

    /// 场景包：tail_lines 只取最后 n 行。
    #[test]
    fn tail_lines_keeps_last_n() {
        let text = "a\nb\nc\nd\ne";
        assert_eq!(tail_lines(text, 3), vec!["c", "d", "e"]);
        assert_eq!(tail_lines(text, 10), vec!["a", "b", "c", "d", "e"]);
        assert!(tail_lines("", 10).is_empty());
    }

    fn synthetic_scenario(id: &str, toml_body: &str) -> (std::path::PathBuf, Vec<Scenario>) {
        // 目录名带测试 id：同进程内测试并行跑，共享目录会互相污染。
        let dir = std::env::temp_dir().join(format!("harness-single-{id}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(dir.join(format!("{id}.toml")), toml_body).expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        (dir, scenarios)
    }

    /// TOML 基本字符串转义：Windows 路径的反斜杠是 TOML 转义符，嵌入场景
    /// TOML 前必须翻倍，否则生成的 toml 在 Windows 上解析失败
    /// （run_parallel 2026-10-16 真实踩坑）；双引号同样转义。Linux 路径
    /// 不含这两类字符，等价于无操作。
    fn toml_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// 合成"脚本场景"：写一个打印固定 JSON 的 sh 脚本 + 引用它的场景 toml。
    ///
    /// 为什么命令经 `sh <script>` 而不是裸 `echo`：Windows 上 PATH 里的
    /// echo.exe（MSYS2 构建）在非 MSYS 父进程下会丢弃参数、只输出一个空行，
    /// `echo {"verdict":"PASS"}` 因此产出空 stdout（2026-10-16 实测），场景
    /// 判定变成 parse 失败。`sh` 在 Linux 与 Git Bash 下均可用（本文件
    /// `run_command_ignores_stderr_for_scenario_json` 已依赖该模式）。
    fn synthetic_script_scenario(
        id: &str,
        json: &str,
        expects: &str,
    ) -> (std::path::PathBuf, Vec<Scenario>) {
        let dir = std::env::temp_dir().join(format!("harness-single-{id}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let script = dir.join(format!("{id}.sh"));
        std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' '{json}'\n"))
            .expect("write script");
        let cmd = format!("sh {}", script.display());
        std::fs::write(
            dir.join(format!("{id}.toml")),
            format!(
                "schema_version = 1\nid = \"t.{id}\"\ncarrier = \"external\"\n[when]\ncommand = \"{}\"\n{expects}",
                toml_escape(&cmd)
            ),
        )
        .expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        (dir, scenarios)
    }

    /// 场景包：run_single 在合成场景上产出结构化失败签名（expect 失败）。
    #[test]
    fn run_single_expect_failure_signature() {
        let (dir, scenarios) = synthetic_script_scenario(
            "sig",
            "{\"verdict\":\"PASS\"}",
            "[[expect]]\nfield = \"verdict\"\nequals = \"FAIL\"\n",
        );
        assert_eq!(scenarios.len(), 1);
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "expect");
        assert_eq!(rep.assertion, "verdict");
        assert!(!rep.key_log_lines.is_empty());
        assert!(rep.duration_ms < 60_000);
        assert!(rep.detail.contains("t.sig.verdict"));
    }

    /// 场景包：run_single 的 fixture 失败签名。
    #[test]
    fn run_single_fixture_failure_signature() {
        let (dir, scenarios) = synthetic_scenario(
            "fx",
            "schema_version = 1\nid = \"t.fx\"\ncarrier = \"engineering\"\n[given]\nfixture = [\"false\"]\n[when]\ncommand = \"echo {\\\"verdict\\\":\\\"PASS\\\"}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "fixture");
        assert_eq!(rep.assertion, "false");
    }

    /// 场景包：run_single 的静态契约（[when] 无 command）→ UNKNOWN（机器接口映射为 BLOCKED）。
    #[test]
    fn run_single_static_contract_is_unknown() {
        let (dir, scenarios) = synthetic_scenario(
            "st",
            "schema_version = 1\nid = \"t.st\"\ntitle = \"静态契约\"\ncarrier = \"engineering\"\n[when]\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "UNKNOWN");
        assert_eq!(rep.failed_step, "lookup");
    }

    /// 场景包：run_single 的平台不匹配 → UNKNOWN。
    #[test]
    fn run_single_platform_mismatch_is_unknown() {
        let (dir, scenarios) = synthetic_scenario(
            "pl",
            "schema_version = 1\nid = \"t.pl\"\ncarrier = \"engineering\"\n[given]\nplatform = \"definitely-not-this-os\"\n[when]\ncommand = \"echo hi\"\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "UNKNOWN");
        assert!(rep.detail.contains("platform contract"));
    }

    /// 场景包：run_single 的 PASS 路径（duration_ms 有界、签名为空）。
    #[test]
    fn run_single_pass_report() {
        let (dir, scenarios) = synthetic_script_scenario(
            "ok",
            "{\"verdict\":\"PASS\"}",
            "[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "PASS");
        assert!(rep.failed_step.is_empty());
        assert!(rep.assertion.is_empty());
        assert!(rep.key_log_lines.is_empty());
        assert!(rep.duration_ms < 60_000);
    }

    /// 场景包：run_single 的 parse 失败签名（输出非 JSON）。
    ///
    /// 评审 WARN：parse 是自修复循环消费的核心签名之一，此前无直接单测锁定。
    #[test]
    fn run_single_parse_failure_signature() {
        let (dir, scenarios) = synthetic_scenario(
            "np",
            "schema_version = 1\nid = \"t.parse\"\ncarrier = \"engineering\"\n[when]\ncommand = \"echo not-json\"\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "parse");
        assert!(rep.assertion.is_empty());
        assert!(!rep.key_log_lines.is_empty());
        assert!(rep.detail.contains("output not JSON"));
    }

    /// 场景包：run_single 的 command 失败签名（spawn_failed）。
    ///
    /// 评审 WARN：spawn_failed 是自修复循环消费的核心签名之一，此前无直接单测锁定。
    /// run_checked_with_timeouts 不走 shell，直接 Command::spawn，命令不存在
    /// 即返回 RunOutcome::SpawnFailed（而非 exit 127）。
    #[test]
    fn run_single_spawn_failed_signature() {
        let (dir, scenarios) = synthetic_scenario(
            "sf",
            "schema_version = 1\nid = \"t.spawn\"\ncarrier = \"engineering\"\n[when]\ncommand = \"nexus-harness-no-such-binary-zzz\"\n",
        );
        let rep = run_single(&scenarios[0], None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "command");
        assert_eq!(rep.assertion, "spawn_failed");
        assert!(rep.detail.contains("cannot run scenario command"));
    }

    /// 并行执行器：多场景并发跑，结果按声明顺序回填、verdict 正确。
    /// 命令不走 shell（按空白切分直接 exec），用脚本文件实现 sleep 交错；
    /// sleep 打乱完成顺序：若实现不按序回填，此测试大概率失败。
    #[test]
    fn run_parallel_keeps_order_and_verdicts() {
        let dir =
            std::env::temp_dir().join(format!("harness-parallel-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        // 偶数 PASS（sleep 交错打乱完成顺序），第 3 个故意 FAIL。
        for i in 0..6 {
            let script = dir.join(format!("run{i}.sh"));
            let body = if i == 2 {
                "#!/bin/sh\necho not-json\n".to_string()
            } else {
                // 脚本直接写文件，不走 TOML：引号用 Rust 转义 \" 即可
                format!(
                    "#!/bin/sh\nsleep 0.{}\necho '{{\"verdict\":\"PASS\"}}'\n",
                    (6 - i) % 5
                )
            };
            std::fs::write(&script, body).expect("write script");
            // 路径嵌入 TOML 前必须转义反斜杠：Windows 上 `C:\Users\...` 的
            // `\U` 是 TOML 非法 unicode 转义，六个场景会全部解析失败被跳过。
            let cmd = format!("sh {}", script.display());
            let toml_body = format!(
                "schema_version = 1\nid = \"t.par{i}\"\ncarrier = \"external\"\n[when]\ncommand = \"{}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
                toml_escape(&cmd)
            );
            std::fs::write(dir.join(format!("s{i}.toml")), toml_body).expect("write toml");
        }
        let scenarios = load_all(&dir, &[""]);
        assert_eq!(scenarios.len(), 6);
        let reports = run_parallel(&scenarios, 3, None, &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reports.len(), 6);
        for (i, rep) in reports.iter().enumerate() {
            if i == 2 {
                assert_eq!(rep.verdict, "FAIL", "scenario {i} should fail");
            } else {
                assert_eq!(rep.verdict, "PASS", "scenario {i} should pass");
            }
        }
        // verdict 分布（仅下标 2 FAIL）即顺序断言：若按完成顺序而非声明顺序
        // 回填，FAIL 会落在随机位置；sleep 交错使完成顺序大概率偏离声明顺序。
    }

    /// 并行度解析：环境变量优先，非法值回退默认；1 表示强制串行。
    /// 用纯函数版本测试，不碰进程全局环境变量（edition 2024 下 set_var 是 unsafe）。
    #[test]
    fn parallel_jobs_env_override() {
        assert_eq!(parallel_jobs_from_env(Some("1".to_string())), 1);
        assert_eq!(parallel_jobs_from_env(Some("0".to_string())), 1);
        assert_eq!(parallel_jobs_from_env(Some("32".to_string())), 32);
        assert_eq!(parallel_jobs_from_env(Some("  4  ".to_string())), 4);
        // 非法值回退到默认（CPU 数，clamp 1..=16）
        let d = parallel_jobs_from_env(Some("not-a-number".to_string()));
        assert!((1..=16).contains(&d));
        let d2 = parallel_jobs_from_env(None);
        assert!((1..=16).contains(&d2));
        // 真实环境变量路径不断言具体值（机器相关），只断言不 panic
        let _ = parallel_jobs();
    }

    #[test]
    fn scenario_timeouts_legacy_and_tier() {
        let legacy = ScenarioTimeouts::legacy();
        assert_eq!(legacy.sandbox.as_secs(), 600);
        assert_eq!(legacy.real_device.as_secs(), 600);
        assert_eq!(legacy.drain.as_secs(), 10);
        let custom = ScenarioTimeouts {
            sandbox: std::time::Duration::from_secs(7),
            real_device: std::time::Duration::from_secs(11),
            drain: std::time::Duration::from_secs(3),
        };
        let mut s = scenario(vec![]);
        s.requires_root = false;
        assert_eq!(custom.for_scenario(&s), std::time::Duration::from_secs(7));
        s.requires_root = true;
        assert_eq!(custom.for_scenario(&s), std::time::Duration::from_secs(11));
    }

    #[test]
    fn scenario_result_carries_duration_and_timed_out() {
        let (dir, _scenarios) = synthetic_script_scenario(
            "dur",
            "{\"verdict\":\"PASS\"}",
            "[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let config = Config {
            policies_dir: dir.join("policies"),
            scenarios_dir: dir.clone(),
            evidence_dir: dir.join("evidence"),
            crates_dir: dir.join("crates"),
            engineering_dir: dir.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        let (results, gate) = run_gate(
            &config,
            "product-scenarios",
            &[""],
            None,
            &ScenarioTimeouts::legacy(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].verdict, "PASS");
        assert!(results[0].duration_ms < 60_000);
        assert!(!results[0].timed_out);
        assert!(gate.duration_ms < 60_000);
    }

    #[cfg(unix)]
    #[test]
    fn fixture_timeout_sets_timed_out() {
        let dir = std::env::temp_dir().join(format!("harness-fixture-to-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let script = dir.join("slow-fixture.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 5\n").expect("write script");
        let body = format!(
            "schema_version = 1\nid = \"t.fxto\"\ncarrier = \"engineering\"\n[given]\nfixture = [\"sh {}\"]\n[when]\ncommand = \"echo {{\\\"verdict\\\":\\\"PASS\\\"}}\"\n",
            toml_escape(&script.to_string_lossy())
        );
        std::fs::write(dir.join("fxto.toml"), body).expect("write toml");
        let scenarios = load_all(&dir, &[""]);
        assert_eq!(scenarios.len(), 1);
        let timeouts = ScenarioTimeouts {
            sandbox: std::time::Duration::from_millis(100),
            real_device: std::time::Duration::from_millis(100),
            drain: std::time::Duration::from_secs(1),
        };
        let rep = run_single(&scenarios[0], None, &timeouts);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "fixture");
        assert_eq!(rep.assertion, "timed_out");
        assert!(rep.timed_out);
        assert!(rep.detail.contains("timed out after 0s"), "{}", rep.detail);
    }

    fn artifacts_with_example(package: &str, example: &str) -> ScenarioArtifacts {
        let mut artifacts = ScenarioArtifacts::default();
        artifacts.examples.insert(
            ExampleKey {
                package: package.to_string(),
                example: example.to_string(),
                features: Vec::new(),
                locked: false,
            },
            PathBuf::from("/tmp/direct-example"),
        );
        artifacts
    }

    #[test]
    fn parse_example_command_to_direct() {
        let artifacts = artifacts_with_example("nexus", "foo");
        match resolve_scenario_command(
            "cargo run --quiet -p nexus --example foo -- --json",
            &artifacts,
        ) {
            ResolvedCommand::Direct {
                program,
                args,
                current_dir,
            } => {
                assert_eq!(program, PathBuf::from("/tmp/direct-example"));
                assert_eq!(args, vec!["--json".to_string()]);
                assert!(current_dir.is_none());
            }
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn parse_bin_default_target() {
        let mut artifacts = ScenarioArtifacts::default();
        artifacts.bins.insert(
            BinKey {
                package: "nexusd".to_string(),
                bin: "nexusd".to_string(),
                features: Vec::new(),
                locked: false,
            },
            PathBuf::from("/tmp/direct-bin"),
        );
        match resolve_scenario_command(
            "cargo run --quiet -p nexusd -- system-proxy e2e --json",
            &artifacts,
        ) {
            ResolvedCommand::Direct { program, args, .. } => {
                assert_eq!(program, PathBuf::from("/tmp/direct-bin"));
                assert_eq!(
                    args,
                    vec![
                        "system-proxy".to_string(),
                        "e2e".to_string(),
                        "--json".to_string()
                    ]
                );
            }
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn parse_locked_and_features_keys() {
        let mut artifacts = ScenarioArtifacts::default();
        artifacts.examples.insert(
            ExampleKey {
                package: "nexus-platform-host".to_string(),
                example: "windows".to_string(),
                features: vec!["platform-windows".to_string()],
                locked: true,
            },
            PathBuf::from("/tmp/direct-windows"),
        );
        let hit = resolve_scenario_command(
            "cargo run -p nexus-platform-host --features platform-windows --locked --example windows -- --json",
            &artifacts,
        );
        assert!(
            matches!(hit, ResolvedCommand::Direct { .. }),
            "locked+features key must hit"
        );
        // 同一个 example 但不带 --locked → 不同 key（未预编）→ 回退旧路径。
        let miss = resolve_scenario_command(
            "cargo run -p nexus-platform-host --features platform-windows --example windows -- --json",
            &artifacts,
        );
        assert!(matches!(miss, ResolvedCommand::Unchanged { .. }));
    }

    #[test]
    fn parse_unknown_forms_unchanged() {
        let artifacts = ScenarioArtifacts::default();
        for command in [
            "cd x && cargo run --example foo",
            "FOO=1 cargo run --example foo",
            "cargo run --release --example foo",
            "cargo test --workspace",
            "nexus-harness run x",
            "cargo run --example foo | tee out",
        ] {
            assert!(
                matches!(
                    resolve_scenario_command(command, &artifacts),
                    ResolvedCommand::Unchanged { .. }
                ),
                "{command}"
            );
        }
    }

    #[test]
    fn resolve_returns_none_current_dir_for_all_276() {
        let repo = Repo::discover().expect("repo must be discoverable");
        let config = Config::load(&repo).expect("config must load");
        let scenarios = load_all(
            &config.scenarios_dir,
            &["product", "engineering", "platform", "regression"],
        );
        let meta = cargo_metadata().expect("cargo metadata");
        let (examples, bins, missing) = collect_scenario_keys(&scenarios, &meta);
        let mut artifacts = ScenarioArtifacts {
            missing,
            ..ScenarioArtifacts::default()
        };
        for key in &examples {
            artifacts
                .examples
                .insert(key.clone(), PathBuf::from("/tmp/direct-example"));
        }
        for key in &bins {
            artifacts
                .bins
                .insert(key.clone(), PathBuf::from("/tmp/direct-bin"));
        }
        let commands: Vec<&String> = scenarios
            .iter()
            .filter_map(|s| s.command.as_ref())
            .collect();
        let mut parseable = 0usize;
        let mut direct = 0usize;
        let mut missing_target = 0usize;
        for command in commands {
            if parse_cargo_run(command).is_none() {
                continue;
            }
            parseable += 1;
            match resolve_scenario_command(command, &artifacts) {
                ResolvedCommand::Direct { current_dir, .. } => {
                    assert!(current_dir.is_none(), "{command}");
                    direct += 1;
                }
                ResolvedCommand::MissingTarget { .. } => missing_target += 1,
                other => panic!(
                    "cargo run command must resolve to Direct/MissingTarget: {command} ({})",
                    match other {
                        ResolvedCommand::Unchanged { .. } => "unchanged",
                        ResolvedCommand::Unavailable { .. } => "unavailable",
                        _ => "other",
                    }
                ),
            }
        }
        // fixes-5 合并注记：master 287 + fixes-5 新增 product.proxy-trojan-fallback-rejected 场景 1 = 288。
        // P3 合并注记：+ product.qos-cake-enabled-path（cargo run -p nexusd --example）= 289。
        // §11.9.5：+ product.nexusd-trojan-credential-probe（cargo run -p nexusd --example）= 290。
        assert_eq!(parseable, 290, "290 cargo-run [when].command");
        assert_eq!(
            missing_target, 22,
            "n3_task_e4 is not declared (contract-first)"
        );
        assert_eq!(direct, 268, "all declared targets resolve to Direct");
    }

    #[cfg(unix)]
    #[test]
    fn direct_execution_inherits_harness_cwd() {
        let timeout = std::time::Duration::from_secs(10);
        let drain = std::time::Duration::from_secs(1);
        let (outcome, stdout, _) =
            run_resolved(Path::new("/bin/pwd"), &[], None, timeout, drain, None);
        assert_eq!(outcome, RunOutcome::Exited(true));
        let expected = std::env::current_dir().expect("cwd");
        assert_eq!(
            stdout.trim(),
            expected.to_string_lossy(),
            "current_dir=None must inherit harness cwd"
        );
        let tmp = std::env::temp_dir().join(format!("harness-cwd-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let (outcome, stdout, _) =
            run_resolved(Path::new("/bin/pwd"), &[], Some(&tmp), timeout, drain, None);
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(outcome, RunOutcome::Exited(true));
        let canonical = tmp.canonicalize().unwrap_or(tmp);
        assert_eq!(stdout.trim(), canonical.to_string_lossy());
    }

    #[test]
    fn prebuild_plan_groups() {
        let repo = Repo::discover().expect("repo must be discoverable");
        let config = Config::load(&repo).expect("config must load");
        let scenarios = load_all(
            &config.scenarios_dir,
            &["product", "engineering", "platform", "regression"],
        );
        let meta = cargo_metadata().expect("cargo metadata");
        let (examples, bins, _missing) = collect_scenario_keys(&scenarios, &meta);
        assert_eq!(
            examples.len() + bins.len(),
            212,
            "208 declared examples + 4 bins (n3_task_e4 is missing/contract-first)"
        );
        assert_eq!(examples.len(), 208);
        assert_eq!(bins.len(), 4);
        let groups = build_groups(&examples, &bins);
        assert_eq!(
            groups.len(),
            16,
            "16 groups after excluding the undeclared n3_task_e4 target (plan expected 17 when counting it)"
        );
        for group in &groups {
            assert!(!group.targets.is_empty());
            for target in &group.targets {
                if group.kind == "example" {
                    assert!(examples.contains(&ExampleKey {
                        package: group.package.clone(),
                        example: target.clone(),
                        features: group.features.clone(),
                        locked: group.locked,
                    }));
                } else {
                    assert!(bins.contains(&BinKey {
                        package: group.package.clone(),
                        bin: target.clone(),
                        features: group.features.clone(),
                        locked: group.locked,
                    }));
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn prebuild_failure_isolated() {
        let dir = std::env::temp_dir().join(format!("harness-prebuild-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (id, example) in [("a", "a"), ("b", "b")] {
            std::fs::write(
                dir.join(format!("{id}.toml")),
                format!(
                    "schema_version = 1\nid = \"t.{id}\"\ncarrier = \"engineering\"\n[when]\ncommand = \"cargo run --quiet -p pkg --example {example} -- {{\\\"verdict\\\":\\\"PASS\\\"}}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n"
                ),
            )
            .unwrap();
        }
        let scenarios = load_all(&dir, &[""]);
        let mut artifacts = ScenarioArtifacts::default();
        artifacts.examples.insert(
            ExampleKey {
                package: "pkg".to_string(),
                example: "a".to_string(),
                features: Vec::new(),
                locked: false,
            },
            PathBuf::from("/bin/echo"),
        );
        artifacts.failures.push(ArtifactBuildFailure {
            package: "pkg".to_string(),
            kind: "example".to_string(),
            target: "b".to_string(),
            detail: "compile error".to_string(),
        });
        let a = scenarios.iter().find(|s| s.id == "t.a").unwrap();
        let b = scenarios.iter().find(|s| s.id == "t.b").unwrap();
        let rep_a = run_single(a, Some(&artifacts), &ScenarioTimeouts::legacy());
        let rep_b = run_single(b, Some(&artifacts), &ScenarioTimeouts::legacy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep_a.verdict, "PASS", "{}", rep_a.detail);
        assert_eq!(rep_b.verdict, "FAIL");
        assert_eq!(rep_b.failed_step, "prebuild");
        assert_eq!(rep_b.assertion, "pkg:example:b");
        assert!(rep_b.detail.contains("compile error"), "{}", rep_b.detail);
    }

    #[test]
    fn run_gate_none_artifacts_keeps_legacy() {
        let (dir, scenarios) = synthetic_script_scenario(
            "legacy",
            "{\"verdict\":\"PASS\"}",
            "[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let config = Config {
            policies_dir: dir.join("policies"),
            scenarios_dir: dir.clone(),
            evidence_dir: dir.join("evidence"),
            crates_dir: dir.join("crates"),
            engineering_dir: dir.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        let (none_results, none_gate) = run_gate(
            &config,
            "product-scenarios",
            &[""],
            None,
            &ScenarioTimeouts::legacy(),
        );
        let empty = ScenarioArtifacts::default();
        let (some_results, some_gate) = run_gate(
            &config,
            "product-scenarios",
            &[""],
            Some(&empty),
            &ScenarioTimeouts::legacy(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(none_results[0].verdict, "PASS");
        assert_eq!(none_gate.verdict, some_gate.verdict);
        assert_eq!(none_results[0].verdict, some_results[0].verdict);
    }

    #[test]
    fn prebuild_never_runs_examples_all() {
        let repo = Repo::discover().expect("repo must be discoverable");
        let config = Config::load(&repo).expect("config must load");
        let scenarios = load_all(
            &config.scenarios_dir,
            &["product", "engineering", "platform", "regression"],
        );
        let meta = cargo_metadata().expect("cargo metadata");
        let (examples, bins, _missing) = collect_scenario_keys(&scenarios, &meta);
        for group in build_groups(&examples, &bins) {
            let args = group_args(&group);
            assert!(!args.iter().any(|a| a == "--examples" || a == "--bins"));
            let mut i = 0;
            while i < args.len() {
                if args[i] == format!("--{}", group.kind) {
                    assert!(
                        group.targets.contains(&args[i + 1]),
                        "unreferenced target in build command: {}",
                        args[i + 1]
                    );
                    i += 2;
                    continue;
                }
                i += 1;
            }
        }
    }

    #[test]
    fn duplicate_example_names_get_unique_snapshots() {
        let mut examples = std::collections::BTreeSet::new();
        for package in ["nexus-fabric", "nexus-path"] {
            examples.insert(ExampleKey {
                package: package.to_string(),
                example: "basic".to_string(),
                features: Vec::new(),
                locked: false,
            });
        }
        let bins = std::collections::BTreeSet::new();
        let duplicates = duplicate_targets(&examples, &bins);
        assert_eq!(
            duplicates,
            std::collections::BTreeSet::from([("example".to_string(), "basic".to_string())])
        );
        let canonical = PathBuf::from("/tmp/examples/basic");
        let a = unique_artifact_path(&canonical, "nexus-fabric", "example", "basic", &[], false);
        let b = unique_artifact_path(&canonical, "nexus-path", "example", "basic", &[], false);
        assert_ne!(a, b, "same-name examples must not share an executable path");
        assert_eq!(a.parent(), canonical.parent());
    }

    // ---- carrier（契约 §2/§4.2） -------------------------------------------

    #[test]
    fn carrier_parse_rejects_unknown() {
        for c in Carrier::ALL {
            assert_eq!(Carrier::parse(c.as_str()), Some(c));
        }
        for bad in [
            "",
            "V9-Connectivity",
            "v9_connectivity",
            "n1",
            "shared",
            "mock-packet-carrier",
            "engineering ",
        ] {
            assert_eq!(Carrier::parse(bad), None, "illegal carrier {bad:?}");
        }
    }

    #[test]
    fn carrier_for_command_rule_table() {
        // ① bootstrap-join（两种 harness 调用形态）
        assert_eq!(
            carrier_for_command("cargo run --quiet -p nexus-harness -- run bootstrap-join --json"),
            Some(Carrier::V9Connectivity)
        );
        assert_eq!(
            carrier_for_command("nexus-harness run bootstrap-join --json"),
            Some(Carrier::V9Connectivity)
        );
        // ② `-p nexus` 必须 token 精确——前缀陷阱逐个否掉。
        assert_eq!(
            carrier_for_command("cargo run --quiet -p nexus --example auto_discovery -- --json"),
            Some(Carrier::V9Connectivity)
        );
        assert_eq!(
            carrier_for_command("cargo run --quiet -p nexusd --example tun -- --json"),
            Some(Carrier::N1Fabric),
            "-p nexusd 不能被 -p nexus 前缀吞掉"
        );
        assert_eq!(
            carrier_for_command("cargo run --quiet -p nexus-harness -- status --json"),
            Some(Carrier::Engineering)
        );
        // ③ v9 内联子命令
        assert_eq!(
            carrier_for_command("nexus-harness run firewall-rules --json"),
            Some(Carrier::V9Connectivity)
        );
        // ⑤ `-p nexus-<name>`（≠ harness）
        assert_eq!(
            carrier_for_command("cargo test --quiet -p nexus-connectivity filter"),
            Some(Carrier::N1Fabric)
        );
        // ⑥ n1 内联子命令
        assert_eq!(
            carrier_for_command("nexus-harness run multipath --json"),
            Some(Carrier::N1Fabric)
        );
        // ⑦ shared-leaf
        assert_eq!(
            carrier_for_command("nexus-harness run qos-cake --json"),
            Some(Carrier::SharedLeaf)
        );
        // ⑨ 首 token harness 自身
        assert_eq!(
            carrier_for_command("nexus-harness status --json"),
            Some(Carrier::Engineering)
        );
        // ⑩ external：解释器 / 仓库脚本
        assert_eq!(
            carrier_for_command("python3 engineering/verifiers/n3_snapshot_staging.py"),
            Some(Carrier::External)
        );
        assert_eq!(
            carrier_for_command("scripts/e4/tun_outbound_ref_flow.sh shadowsocks"),
            Some(Carrier::External)
        );
        assert_eq!(carrier_for_command("bash run.sh"), Some(Carrier::External));
    }

    #[test]
    fn carrier_for_command_order_sensitive_cases() {
        // C2-② 的 11 例：先命中 v9/n1/shared，后命中 engineering。
        assert_eq!(
            carrier_for_command("cargo run --quiet -p nexus-harness -- run bootstrap-join --json"),
            Some(Carrier::V9Connectivity)
        );
        for sub in [
            "virtual-subnet-tunnel",
            "virtual-subnet-mesh",
            "multihop-routing",
            "mesh-dns",
            "firewall-rules",
            "bandwidth-qos",
            "auto-reconnect",
        ] {
            let cmd = format!("nexus-harness run {sub} --json");
            assert_eq!(
                carrier_for_command(&cmd),
                Some(Carrier::V9Connectivity),
                "{cmd}"
            );
        }
        for sub in ["dns-unified", "multipath"] {
            let cmd = format!("nexus-harness run {sub} --json");
            assert_eq!(carrier_for_command(&cmd), Some(Carrier::N1Fabric), "{cmd}");
        }
        assert_eq!(
            carrier_for_command("nexus-harness run qos-cake --json"),
            Some(Carrier::SharedLeaf)
        );
    }

    #[test]
    fn carrier_for_command_unclassified_returns_none() {
        for cmd in [
            "echo hi",
            "true",
            "",
            "cargo run --quiet -p pkg --example x",
        ] {
            assert_eq!(carrier_for_command(cmd), None, "{cmd:?}");
        }
    }

    fn carrier_toml(id: &str, carrier_line: &str) -> String {
        format!("schema_version = 1\nid = \"{id}\"\n{carrier_line}[when]\ncommand = \"echo hi\"\n")
    }

    #[test]
    fn load_rejects_missing_or_invalid_carrier() {
        let dir = std::env::temp_dir().join(format!("harness-carrier-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("missing.toml"),
            "schema_version = 1\nid = \"t.missing\"\n[when]\ncommand = \"echo hi\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("invalid.toml"),
            carrier_toml("t.invalid", "carrier = \"nonsense\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("notstring.toml"),
            carrier_toml("t.notstring", "carrier = 42\n"),
        )
        .unwrap();
        let (scenarios, errors) = load_all_reporting(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(scenarios.is_empty());
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("缺顶层 carrier")));
        assert!(errors.iter().any(|e| e.contains("非法 carrier")));
        assert!(errors.iter().any(|e| e.contains("carrier 非字符串")));
    }

    #[test]
    fn load_rejects_declared_derivation_mismatch() {
        let dir = std::env::temp_dir().join(format!("harness-carrier-mis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.mis\"\ncarrier = \"v9-connectivity\"\n[when]\ncommand = \"cargo run --quiet -p nexusd --example tun -- --json\"\n",
        )
        .unwrap();
        let (scenarios, errors) = load_all_reporting(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(scenarios.is_empty());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("与派生值不一致"), "{}", errors[0]);
    }

    #[test]
    fn load_accepts_declared_when_underivable() {
        // 派生 None（合成命令）→ 声明值不被否决（仓库级 totality 由 index --check 强制）。
        let (dir, scenarios) = synthetic_scenario(
            "underivable",
            "schema_version = 1\nid = \"t.underivable\"\ncarrier = \"external\"\n[when]\ncommand = \"echo hi\"\n",
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].carrier, Carrier::External);
    }

    fn carrier_gate_config(dir: &std::path::Path) -> Config {
        Config {
            policies_dir: dir.join("policies"),
            scenarios_dir: dir.to_path_buf(),
            evidence_dir: dir.join("evidence"),
            crates_dir: dir.join("crates"),
            engineering_dir: dir.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        }
    }

    #[test]
    fn load_all_reports_errors_instead_of_silent_skip() {
        let dir = std::env::temp_dir().join(format!("harness-load-rep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("good.toml"),
            carrier_toml("t.good", "carrier = \"engineering\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("bad.toml"),
            "schema_version = 1\nid = \"t.bad\"\n[when]\ncommand = \"echo hi\"\n",
        )
        .unwrap();
        let (scenarios, errors) = load_all_reporting(&dir, &[""]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].id, "t.good");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("bad.toml"));
    }

    #[test]
    fn run_gate_fails_on_load_error() {
        // 全部场景都坏：必须是 FAIL，而不是 "no scenario files declared" PASS。
        let dir = std::env::temp_dir().join(format!("harness-gate-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("bad.toml"),
            "schema_version = 1\nid = \"t.bad\"\ncarrier = \"v9-connectivity\"\n[when]\ncommand = \"cargo run --quiet -p nexusd --example tun -- --json\"\n",
        )
        .unwrap();
        let config = carrier_gate_config(&dir);
        let (results, gate) = run_gate(
            &config,
            "product-scenarios",
            &[""],
            None,
            &ScenarioTimeouts::legacy(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(gate.verdict, "FAIL", "{}", gate.detail);
        assert!(
            !gate.detail.contains("no scenario files declared"),
            "{}",
            gate.detail
        );
        assert!(gate.detail.contains("failed to load"), "{}", gate.detail);
        assert!(results.is_empty());
    }
}
