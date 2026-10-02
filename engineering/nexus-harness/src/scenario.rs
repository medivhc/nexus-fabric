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
    pub platform: Option<String>,
    pub command: Option<String>,
    pub expects: Vec<ScenarioExpect>,
}

#[derive(Clone)]
pub struct ScenarioResult {
    pub id: String,
    pub verdict: String,
    pub detail: String,
}

fn load_file(path: &PathBuf) -> Option<Scenario> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: toml::Value = toml::from_str(&text).ok()?;
    let id = v.get("id")?.as_str()?.to_string();
    let platform = v
        .get("given")
        .and_then(|g| g.get("platform"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
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
                        ExpectKind::Equals(toml_scalar_to_json(x))
                    } else if let Some(list) = e.get("one_of").and_then(toml::Value::as_array) {
                        ExpectKind::OneOf(list.iter().map(toml_scalar_to_json).collect())
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
        platform,
        command,
        expects,
    })
}

fn toml_scalar_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        _ => Value::Null,
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
            if let Some(s) = load_file(&f) {
                out.push(s);
            }
        }
    }
    out
}

/// Evaluate a scenario against a command's JSON output.
fn evaluate(scenario: &Scenario, output: &Value) -> Result<(), String> {
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
            return Err(format!(
                "expect {}.{} failed (actual: {})",
                scenario.id,
                expect.path,
                actual
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "<missing>".to_string())
            ));
        }
    }
    Ok(())
}

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Run a [when].command, resolving "nexus-harness" to the current executable so
/// the harness can self-host its own scenario gate.
///
/// 有界执行：场景命令必须在超时内结束。用 spawn + try_wait
/// 轮询代替 Command::output()——output() 会阻塞读 pipe 到 EOF，若场景的
/// 孤儿子进程（如 E4 的 netns child）持有 pipe 写端，EOF 永不到、harness
/// 永挂（2026-10-02 n1_roam 真实踩坑）。超时则 kill 直接子进程并判失败；
/// 输出收集不等待 EOF，取读线程已拿到的数据。
fn run_command(command: &str) -> (String, String) {
    use std::time::Duration;
    run_command_with_timeouts(command, Duration::from_secs(600), Duration::from_secs(10))
}

/// 见 run_command 注释。timeout 参数化仅供回归测试注入短超时。
fn run_command_with_timeouts(
    command: &str,
    scenario_timeout: std::time::Duration,
    drain_timeout: std::time::Duration,
) -> (String, String) {
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
    let mut child = match Command::new(&program)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false.to_string(), format!("cannot run {program}: {e}")),
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
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {
                if start.elapsed() >= scenario_timeout {
                    let _ = child.kill();
                    // 尽力回收直接子进程；孤儿孙进程由其自行退出，
                    // 不阻塞等待（它们的 pipe 写端已无关大局）。
                    let _ = child.try_wait();
                    break true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break false,
        }
    };

    let deadline = Instant::now() + drain_timeout;
    let mut stdout = Vec::new();
    for _ in 0..2 {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok((true, b)) => stdout = b,
            // stderr 照常抽干（避免 pipe 背压阻塞子进程），但不参与机器判定：
            // 场景命令的机器可读输出必须是纯 stdout JSON，人类可读日志走 stderr。
            // 历史教训：曾经把 stderr 拼进判定文本，导致 eprintln! 的日志行
            // 破坏 JSON 解析（2026-10-02 full verify composition-root / workspace-sync-authz 误判）。
            Ok((false, _)) => {}
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&stdout).into_owned();
    if timed_out {
        (
            false.to_string(),
            format!(
                "scenario command timed out after {}s: {program}",
                scenario_timeout.as_secs()
            ),
        )
    } else {
        // 调用方忽略首元素、只按输出 JSON 做期望判定（见 run_gate），
        // 此处保持与原语义一致：命令跑完即透出原始输出。
        (true.to_string(), text)
    }
}

/// Run all command-scenarios in the given subdirs; static ones are recorded
/// UNKNOWN. Returns (results, gate) — gate is FAIL if any scenario FAIL.
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
        if let Some(plat) = &s.platform {
            let current_plat = if cfg!(windows) {
                "windows"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "macos") {
                "macos"
            } else {
                "other"
            };
            if plat != current_plat {
                results.push(ScenarioResult {
                    id: s.id.clone(),
                    verdict: "UNKNOWN".to_string(),
                    detail: format!("platform contract ({plat} required, host is {current_plat})"),
                });
                continue;
            }
        }
        match &s.command {
            None => results.push(ScenarioResult {
                id: s.id.clone(),
                verdict: "UNKNOWN".to_string(),
                detail: "static contract, runtime not exercisable by harness (no [when].command)"
                    .to_string(),
            }),
            Some(cmd) => {
                let (_, out) = run_command(cmd);
                match serde_json::from_str::<Value>(&out) {
                    Ok(json) => match evaluate(s, &json) {
                        Ok(()) => results.push(ScenarioResult {
                            id: s.id.clone(),
                            verdict: "PASS".to_string(),
                            detail: format!(
                                "command ran, all {} expectations held",
                                s.expects.len()
                            ),
                        }),
                        Err(e) => {
                            failed = true;
                            results.push(ScenarioResult {
                                id: s.id.clone(),
                                verdict: "FAIL".to_string(),
                                detail: e,
                            });
                        }
                    },
                    Err(e) => {
                        failed = true;
                        results.push(ScenarioResult {
                            id: s.id.clone(),
                            verdict: "FAIL".to_string(),
                            detail: format!("output not JSON ({e}): {}", out.trim()),
                        });
                    }
                }
            }
        }
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
            platform: None,
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
        let (ok, out) =
            run_command_with_timeouts("sleep 30", Duration::from_secs(2), Duration::from_secs(1));
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
        );
        let elapsed = start.elapsed();
        assert_eq!(ok, "true");
        assert!(
            elapsed < Duration::from_secs(15),
            "run_command hung on orphaned pipe holder: {elapsed:?}"
        );
    }
}
