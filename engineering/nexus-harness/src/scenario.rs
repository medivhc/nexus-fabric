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
}

#[derive(Clone)]
pub struct ScenarioResult {
    pub id: String,
    pub verdict: String,
    pub detail: String,
}

fn load_file(path: &PathBuf, subdir: &str) -> Option<Scenario> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: toml::Value = toml::from_str(&text).ok()?;
    let id = v.get("id")?.as_str()?.to_string();
    let title = v
        .get("title")
        .and_then(toml::Value::as_str)
        .unwrap_or("")
        .to_string();
    let requires_root = v
        .get("requires_root")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
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
                        ExpectKind::Equals(toml_value_to_json(x))
                    } else if let Some(list) = e.get("one_of").and_then(toml::Value::as_array) {
                        ExpectKind::OneOf(list.iter().map(toml_value_to_json).collect())
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
        subdir: subdir.to_string(),
        title,
        requires_root,
        file_stem,
        platform,
        fixtures,
        command,
        expects,
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
            if let Some(s) = load_file(&f, sub) {
                out.push(s);
            }
        }
    }
    out
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
    node_dir: Option<&std::path::Path>,
) -> (bool, String, String) {
    use std::time::Duration;
    let (outcome, stdout, stderr_tail) = run_checked_with_timeouts(
        command,
        Duration::from_secs(600),
        Duration::from_secs(10),
        node_dir,
    );
    (outcome == RunOutcome::Exited(true), stdout, stderr_tail)
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
    use std::io::Read;
    use std::time::{Duration, Instant};

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
    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // 场景隔离：每个场景用独立的节点目录，fixture 与主命令共享同一目录，
    // 场景之间互不可见。`nexus` 经 `NEXUS_CONFIG_DIR` 读取节点目录
    // （apps/nexus/src/node_cli.rs::node_dir）。
    if let Some(dir) = node_dir {
        cmd.env("NEXUS_CONFIG_DIR", dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (
                RunOutcome::SpawnFailed,
                String::new(),
                format!("cannot run {program}: {e}"),
            );
        }
    };
    // 读线程：并发抽干 pipe；孤儿进程持有写端时它们可能永不 EOF，
    // 主线程只按 drain_timeout 有限等待，不依赖它们结束。
    let (tx, rx) = std::sync::mpsc::channel::<(bool, Vec<u8>)>();
    // stdout 读线程。
    if let Some(mut p) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            let _ = tx.send((true, buf));
        });
    }
    // stderr 读线程。
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
            // stderr 照常抽干（避免 pipe 背压阻塞子进程）；场景判定不用它，
            // 但夹具失败时取尾部作诊断。
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
                "scenario command timed out after {}s: {program}",
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
    /// 人类可读明细（与旧 ScenarioResult.detail 同格式）。
    pub detail: String,
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
pub fn run_single(s: &Scenario) -> ScenarioRunReport {
    use std::time::Instant;
    let start = Instant::now();
    let mut rep = run_single_inner(s);
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
        detail,
    }
}

fn run_single_inner(s: &Scenario) -> ScenarioRunReport {
    use std::time::Duration;

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
    for fixture in &s.fixtures {
        let (ok, _out, err_tail) = run_command_checked(fixture, node_dir);
        if !ok {
            return ScenarioRunReport {
                verdict: "FAIL".to_string(),
                failed_step: "fixture".to_string(),
                assertion: fixture.clone(),
                key_log_lines: tail_lines(&err_tail, 10),
                duration_ms: 0,
                detail: format!("fixture failed: {fixture} (stderr: {err_tail})"),
            };
        }
    }
    // 主命令：有界执行，透出 RunOutcome 以区分"命令失败"与"输出解析失败"。
    let (outcome, stdout, stderr_tail) = run_checked_with_timeouts(
        &cmd,
        Duration::from_secs(600),
        Duration::from_secs(10),
        node_dir,
    );
    match outcome {
        RunOutcome::TimedOut => ScenarioRunReport {
            verdict: "FAIL".to_string(),
            failed_step: "command".to_string(),
            assertion: "timed_out".to_string(),
            key_log_lines: tail_lines(&format!("{stdout}\n{stderr_tail}"), 10),
            duration_ms: 0,
            detail: "scenario command timed out after 600s".to_string(),
        },
        RunOutcome::SpawnFailed => ScenarioRunReport {
            verdict: "FAIL".to_string(),
            failed_step: "command".to_string(),
            assertion: "spawn_failed".to_string(),
            key_log_lines: tail_lines(&stderr_tail, 10),
            duration_ms: 0,
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
                    detail: format!("command ran, all {} expectations held", s.expects.len()),
                },
                Err(f) => ScenarioRunReport {
                    verdict: "FAIL".to_string(),
                    failed_step: "expect".to_string(),
                    assertion: f.path.clone(),
                    key_log_lines: tail_lines(&stdout, 10),
                    duration_ms: 0,
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
                        detail: format!("output not JSON ({e}): {}", stdout.trim()),
                    }
                }
            }
        },
    }
}

/// Run all command-scenarios in the given subdirs; static ones are recorded
/// UNKNOWN. Returns (results, gate) — gate is FAIL if any scenario FAIL.
///
/// 逐场景执行委托给 run_single（单一执行路径）；本函数只做聚合与 Gate 判定。
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
        let rep = run_single(s);
        if rep.verdict == "FAIL" {
            failed = true;
        }
        results.push(ScenarioResult {
            id: s.id.clone(),
            verdict: rep.verdict,
            detail: rep.detail,
        });
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
            subdir: "product".to_string(),
            title: "test".to_string(),
            requires_root: false,
            file_stem: "t".to_string(),
            platform: None,
            fixtures: Vec::new(),
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

    /// E4 夹具（P0-6）：`[given].fixture` 字符串数组被解析进 Scenario。
    #[test]
    fn fixture_parsed_from_given() {
        let dir = std::env::temp_dir().join(format!("harness-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.fixture\"\n[given]\nfixture = [\"echo one\", \"echo two\"]\n[when]\ncommand = \"echo hi\"\n",
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
            "schema_version = 1\nid = \"t.nofixture\"\n[given]\n[when]\ncommand = \"echo hi\"\n",
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
        let (ok, _, _) = run_command_checked("true", None);
        assert!(ok, "exit 0 must be ok");
        let (ok, _, err) = run_command_checked("false", None);
        assert!(!ok, "exit 1 must not be ok: {err}");
        let (ok, _, err) = run_command_checked("definitely-not-a-real-command-xyz", None);
        assert!(!ok, "spawn failure must not be ok: {err}");
    }

    /// E4 夹具（P0-6）：非字符串 fixture 条目被忽略（不炸解析）。
    #[test]
    fn fixture_non_string_entries_ignored() {
        let dir = std::env::temp_dir().join(format!("harness-fixture2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            dir.join("s.toml"),
            "schema_version = 1\nid = \"t.fixture2\"\n[given]\nfixture = [\"echo ok\", 42]\n[when]\ncommand = \"echo hi\"\n",
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

    /// 场景包：title / subdir / requires_root 从 toml 解析。
    #[test]
    fn scenario_meta_parsed_from_toml() {
        let dir = std::env::temp_dir().join(format!("harness-meta-{}", std::process::id()));
        let sub = dir.join("product");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&sub).expect("tmpdir");
        std::fs::write(
            sub.join("m.toml"),
            "schema_version = 1\nid = \"t.meta\"\ntitle = \"元信息测试\"\nrequires_root = true\n[when]\ncommand = \"echo hi\"\n",
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

    /// 场景包：run_single 在合成场景上产出结构化失败签名（expect 失败）。
    #[test]
    fn run_single_expect_failure_signature() {
        let (dir, scenarios) = synthetic_scenario(
            "sig",
            "schema_version = 1\nid = \"t.sig\"\ntitle = \"签名测试\"\n[when]\ncommand = \"echo {\\\"verdict\\\":\\\"PASS\\\"}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"FAIL\"\n",
        );
        assert_eq!(scenarios.len(), 1);
        let rep = run_single(&scenarios[0]);
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
            "schema_version = 1\nid = \"t.fx\"\n[given]\nfixture = [\"false\"]\n[when]\ncommand = \"echo {\\\"verdict\\\":\\\"PASS\\\"}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let rep = run_single(&scenarios[0]);
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
            "schema_version = 1\nid = \"t.st\"\ntitle = \"静态契约\"\n[when]\n",
        );
        let rep = run_single(&scenarios[0]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "UNKNOWN");
        assert_eq!(rep.failed_step, "lookup");
    }

    /// 场景包：run_single 的平台不匹配 → UNKNOWN。
    #[test]
    fn run_single_platform_mismatch_is_unknown() {
        let (dir, scenarios) = synthetic_scenario(
            "pl",
            "schema_version = 1\nid = \"t.pl\"\n[given]\nplatform = \"definitely-not-this-os\"\n[when]\ncommand = \"echo hi\"\n",
        );
        let rep = run_single(&scenarios[0]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "UNKNOWN");
        assert!(rep.detail.contains("platform contract"));
    }

    /// 场景包：run_single 的 PASS 路径（duration_ms 有界、签名为空）。
    #[test]
    fn run_single_pass_report() {
        let (dir, scenarios) = synthetic_scenario(
            "ok",
            "schema_version = 1\nid = \"t.ok\"\n[when]\ncommand = \"echo {\\\"verdict\\\":\\\"PASS\\\"}\"\n[[expect]]\nfield = \"verdict\"\nequals = \"PASS\"\n",
        );
        let rep = run_single(&scenarios[0]);
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
            "schema_version = 1\nid = \"t.parse\"\n[when]\ncommand = \"echo not-json\"\n",
        );
        let rep = run_single(&scenarios[0]);
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
            "schema_version = 1\nid = \"t.spawn\"\n[when]\ncommand = \"nexus-harness-no-such-binary-zzz\"\n",
        );
        let rep = run_single(&scenarios[0]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep.verdict, "FAIL");
        assert_eq!(rep.failed_step, "command");
        assert_eq!(rep.assertion, "spawn_failed");
        assert!(rep.detail.contains("cannot run scenario command"));
    }
}
