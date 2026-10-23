//! Gate implementations: whitespace / format / check / clippy / tests /
//! affected analysis / policy validation.

use crate::config::Config;
use crate::env::{Repo, cargo_metadata, path_is_within};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone)]
pub struct Gate {
    pub name: String,
    pub verdict: String,
    pub detail: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub skipped_by_deadline: bool,
}

impl Gate {
    pub fn ok(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "PASS".to_string(),
            detail: detail.to_string(),
            duration_ms: 0,
            timed_out: false,
            skipped_by_deadline: false,
        }
    }
    pub fn fail(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "FAIL".to_string(),
            detail: detail.to_string(),
            duration_ms: 0,
            timed_out: false,
            skipped_by_deadline: false,
        }
    }
    pub fn unknown(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "UNKNOWN".to_string(),
            detail: detail.to_string(),
            duration_ms: 0,
            timed_out: false,
            skipped_by_deadline: false,
        }
    }
    /// 全局截止导致的未执行/被中断门：fail-closed，绝不当作 PASS。
    pub fn blocked(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "BLOCKED".to_string(),
            detail: detail.to_string(),
            duration_ms: 0,
            timed_out: false,
            skipped_by_deadline: true,
        }
    }
}

/// 单次命令/单门的有效预算。`deadline` 为绝对时刻；`None` = 无限制。
#[derive(Clone, Copy)]
pub struct GateBudget {
    pub deadline: Option<std::time::Instant>,
}

impl GateBudget {
    pub fn unlimited() -> GateBudget {
        GateBudget { deadline: None }
    }
    pub fn from_limit(limit: Option<std::time::Duration>) -> GateBudget {
        GateBudget {
            deadline: limit.map(|d| std::time::Instant::now() + d),
        }
    }
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(std::time::Instant::now()))
    }
    pub fn expired(&self) -> bool {
        self.remaining().is_some_and(|r| r.is_zero())
    }
}

/// 有界子进程执行结果。`TimedOut.text` 为已抽干的输出（尽力而为）。
pub enum CommandOutcome {
    Exited { success: bool, text: String },
    TimedOut { text: String },
    SpawnFailed { detail: String },
}

/// 用预算包住一次门执行并写入 `duration_ms`（只计时，不参与判定）。
pub(crate) fn timed<F: FnOnce() -> Gate>(f: F) -> Gate {
    let start = std::time::Instant::now();
    let mut g = f();
    g.duration_ms = start.elapsed().as_millis() as u64;
    g
}

/// 在 repo 根目录有界执行命令；超时只 kill 直接子进程（孙进程不等待，
/// 与 `scenario.rs` 的既有语义一致），读线程以 10s drain 超时收尾。
pub fn run_bounded(
    root: &PathBuf,
    program: &str,
    args: &[&str],
    budget: GateBudget,
) -> CommandOutcome {
    run_bounded_env(root, program, args, budget, &[])
}

fn run_bounded_env(
    root: &PathBuf,
    program: &str,
    args: &[&str],
    budget: GateBudget,
    envs: &[(&str, &std::path::Path)],
) -> CommandOutcome {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CommandOutcome::SpawnFailed {
                detail: format!("failed to run {program}: {e}"),
            };
        }
    };
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

    let mut exit_status = None;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if budget.expired() {
                    let _ = child.kill();
                    let _ = child.try_wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    // 判定用退出状态：超时 / 等待失败的进程一律不视为成功。
    let success = exit_status.is_some_and(|status| status.success()) && !timed_out;

    let deadline = Instant::now() + Duration::from_secs(10);
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
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    if timed_out {
        CommandOutcome::TimedOut { text }
    } else {
        CommandOutcome::Exited { success, text }
    }
}

/// Run a command in the repo root; returns (success, trimmed output tail).
#[allow(dead_code)]
fn run_at(root: &PathBuf, program: &str, args: &[&str]) -> (bool, String) {
    let (ok, text) = run_at_full(root, program, args);
    let tail: Vec<&str> = text.lines().rev().take(12).collect();
    let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
    (ok, tail)
}

/// Run a command in the repo root; returns (success, full combined output).
/// 无预算调用（辅助探测/不需要门预算的旧路径）：内部走 `run_bounded` 的无限制预算。
fn run_at_full(root: &PathBuf, program: &str, args: &[&str]) -> (bool, String) {
    match run_bounded(root, program, args, GateBudget::unlimited()) {
        CommandOutcome::Exited { success, text } => (success, text),
        CommandOutcome::TimedOut { text } => (false, text),
        CommandOutcome::SpawnFailed { detail } => (false, detail),
    }
}

/// Current Cargo artifacts, passed only to child test commands (never PATH).
struct ProductBinaries {
    cli: PathBuf,
    daemon: PathBuf,
}

fn product_binaries(
    repo: &Repo,
    meta: &Value,
    packages: &[String],
    gate_name: &str,
    budget: GateBudget,
) -> Result<Option<ProductBinaries>, GateFailure> {
    if !packages
        .iter()
        .any(|name| name == "nexus" || name == "nexusd")
    {
        return Ok(None);
    }
    build_product_binaries(repo, meta, gate_name, "cargo", budget).map(Some)
}

/// 把内部失败映射为门结果：超时保留 `timed_out=true`（fail-closed）。
fn fail_from(name: &str, e: GateFailure) -> Gate {
    let mut g = Gate::fail(name, &e.detail);
    g.timed_out = e.timed_out;
    g
}

/// 带 fail-closed 标记的内部失败：`timed_out` 决定门是否记 `timed_out=true`。
struct GateFailure {
    detail: String,
    timed_out: bool,
}

impl GateFailure {
    fn new(detail: String) -> GateFailure {
        GateFailure {
            detail,
            timed_out: false,
        }
    }
}

fn budget_secs(budget: GateBudget) -> u64 {
    budget.remaining().map(|d| d.as_secs()).unwrap_or(0)
}

/// Always ask Cargo to build, even if executables exist: Cargo owns freshness.
/// Read actual executable paths from artifacts, including custom target dirs.
fn build_product_binaries(
    repo: &Repo,
    meta: &Value,
    gate_name: &str,
    program: &str,
    budget: GateBudget,
) -> Result<ProductBinaries, GateFailure> {
    let args = [
        "build",
        "-p",
        "nexus",
        "--bin",
        "nexus",
        "-p",
        "nexusd",
        "--bin",
        "nexusd",
        "--message-format=json",
    ];
    let secs = budget_secs(budget);
    let stdout = match run_bounded(&repo.root, program, &args, budget) {
        CommandOutcome::Exited {
            success: true,
            text,
        } => text,
        CommandOutcome::Exited {
            success: false,
            text,
        } => {
            return Err(GateFailure::new(format!(
                "current CLI/daemon prebuild: cargo {} failed:\n{}",
                args.join(" "),
                text
            )));
        }
        CommandOutcome::TimedOut { .. } => {
            return Err(GateFailure {
                detail: format!("gate '{gate_name}' timed out after {secs}s"),
                timed_out: true,
            });
        }
        CommandOutcome::SpawnFailed { detail } => {
            return Err(GateFailure::new(format!(
                "current CLI/daemon prebuild: cargo {}: {detail}",
                args.join(" ")
            )));
        }
    };
    binaries_from_artifacts(repo, meta, stdout.as_bytes()).map_err(GateFailure::new)
}

fn binaries_from_artifacts(
    repo: &Repo,
    meta: &Value,
    stdout: &[u8],
) -> Result<ProductBinaries, String> {
    // run_bounded 合并 stdout+stderr；只解析 JSON 对象行（cargo 的进度
    // 行在 stderr），但 JSON 行本身解析失败仍然 fail-closed。
    let mut artifacts: Vec<Value> = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        artifacts.push(serde_json::from_str(line).map_err(|e| {
            format!("current CLI/daemon prebuild: malformed Cargo artifact JSON: {e}")
        })?);
    }
    let executable = |name: &str| -> Result<PathBuf, String> {
        let package = meta["packages"]
            .as_array()
            .and_then(|packages| {
                packages.iter().find(|p| {
                    p["name"].as_str() == Some(name)
                        && meta["workspace_members"]
                            .as_array()
                            .is_some_and(|members| members.contains(&p["id"]))
                })
            })
            .ok_or_else(|| {
                format!("current CLI/daemon prebuild: missing workspace package {name}")
            })?;
        let mut paths = artifacts
            .iter()
            .filter(|artifact| {
                artifact["reason"] == "compiler-artifact"
                    && artifact["package_id"] == package["id"]
                    && artifact["target"]["name"].as_str() == Some(name)
                    && artifact["target"]["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
                    && artifact["profile"]["test"] == false
            })
            .filter_map(|artifact| artifact["executable"].as_str());
        let path = paths.next().ok_or_else(|| {
            format!("current CLI/daemon prebuild: cargo returned no {name} executable artifact")
        })?;
        if paths.next().is_some() {
            return Err(format!(
                "current CLI/daemon prebuild: ambiguous {name} executable artifacts"
            ));
        }
        let path = repo.root.join(path);
        if !path.is_file() {
            return Err(format!(
                "current CLI/daemon prebuild: {name} executable missing: {}",
                path.display()
            ));
        }
        Ok(path)
    };
    Ok(ProductBinaries {
        cli: executable("nexus")?,
        daemon: executable("nexusd")?,
    })
}

fn cargo_gate(repo: &Repo, name: &str, args: &[&str], budget: GateBudget) -> Gate {
    cargo_test_gate(repo, name, args, None, budget)
}

/// 执行一条 cargo 命令并映射为门结果。超时 = FAIL + `timed_out=true`
/// （fail-closed），detail 固定为 `gate '<name>' timed out after <n>s`。
fn cargo_test_gate(
    repo: &Repo,
    name: &str,
    args: &[&str],
    binaries: Option<&ProductBinaries>,
    budget: GateBudget,
) -> Gate {
    let secs = budget_secs(budget);
    let envs: Vec<(&str, &std::path::Path)> = binaries
        .map(|b| {
            vec![
                ("NEXUS_N3_TEST_CLI_BIN", b.cli.as_path()),
                ("NEXUS_N3_TEST_DAEMON_BIN", b.daemon.as_path()),
            ]
        })
        .unwrap_or_default();
    match run_bounded_env(&repo.root, "cargo", args, budget, &envs) {
        CommandOutcome::Exited { success: true, .. } => Gate::ok(name, "ok"),
        CommandOutcome::Exited {
            success: false,
            text,
        } => {
            let tail = text
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            Gate::fail(name, &format!("cargo {} failed:\n{tail}", args.join(" ")))
        }
        CommandOutcome::TimedOut { .. } => {
            let mut g = Gate::fail(name, &format!("gate '{name}' timed out after {secs}s"));
            g.timed_out = true;
            g
        }
        CommandOutcome::SpawnFailed { detail } => Gate::fail(name, &detail),
    }
}

pub fn whitespace_gate(repo: &Repo, _budget: GateBudget) -> Gate {
    let mut problems: Vec<String> = Vec::new();
    for check in [
        &["diff", "--check"][..],
        &["diff", "--cached", "--check"][..],
    ] {
        if let Ok(out) = repo.git(check) {
            if !out.is_empty() {
                problems.push(out);
            }
        }
    }
    if problems.is_empty() {
        Gate::ok("whitespace", "no whitespace errors")
    } else {
        Gate::fail("whitespace", &problems.join("\n"))
    }
}

pub fn format_gate(repo: &Repo, budget: GateBudget) -> Gate {
    cargo_gate(repo, "format", &["fmt", "--all", "--", "--check"], budget)
}

pub fn check_gate(repo: &Repo, budget: GateBudget) -> Gate {
    cargo_gate(
        repo,
        "check",
        &["check", "--workspace", "--all-targets"],
        budget,
    )
}

pub fn clippy_gate(repo: &Repo, budget: GateBudget) -> Gate {
    cargo_gate(
        repo,
        "clippy",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        budget,
    )
}

/// Unit tests of the harness itself (selected properties gate).
pub fn selected_properties_gate(repo: &Repo, budget: GateBudget) -> Gate {
    cargo_gate(
        repo,
        "selected-properties",
        &["test", "-p", "nexus-harness"],
        budget,
    )
}

pub fn workspace_tests_gate(repo: &Repo, budget: GateBudget) -> Gate {
    let meta = match cargo_metadata() {
        Ok(meta) => meta,
        Err(e) => return Gate::unknown("workspace-tests", &format!("cargo metadata failed: {e}")),
    };
    let binaries =
        match product_binaries(repo, &meta, &member_names(&meta), "workspace-tests", budget) {
            Ok(binaries) => binaries,
            Err(e) => return fail_from("workspace-tests", e),
        };
    let g = cargo_test_gate(
        repo,
        "workspace-tests",
        &["test", "--workspace"],
        binaries.as_ref(),
        budget,
    );
    Gate {
        name: "workspace-tests".to_string(),
        ..g
    }
}

/// Affected analysis: changed files -> owning crates -> direct reverse deps.
/// Tests every affected crate; no changes => PASS.
pub fn affected_tests_gate(repo: &Repo, _config: &Config, budget: GateBudget) -> Gate {
    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => return Gate::unknown("affected-tests", &format!("cargo metadata failed: {e}")),
    };
    let members = member_names(&meta);
    let affected = match changed_member_names(repo, &meta, &members) {
        Ok(affected) => affected,
        Err(e) => return Gate::unknown("affected-tests", &e),
    };
    if affected.is_empty() {
        return Gate::ok("affected-tests", "no affected crates changed");
    }
    let binaries = match product_binaries(repo, &meta, &affected, "affected-tests", budget) {
        Ok(binaries) => binaries,
        Err(e) => return fail_from("affected-tests", e),
    };
    let mut failures: Vec<String> = Vec::new();
    for name in &affected {
        let g = cargo_test_gate(
            repo,
            "affected-tests",
            &["test", "-p", name],
            binaries.as_ref(),
            budget,
        );
        if g.verdict == "FAIL" {
            failures.push(format!("{name}: {}", g.detail));
        }
    }
    if failures.is_empty() {
        Gate::ok(
            "affected-tests",
            &format!("tested: {}", affected.join(", ")),
        )
    } else {
        Gate::fail("affected-tests", &failures.join("\n"))
    }
}

/// Workspace member package names (from cargo metadata). Members are matched
/// by full PackageId against `workspace_members` — the id format is
/// `path+file:///.../dir#<version>` (no package name), so name/version parsing
/// is avoided entirely.
fn member_names(meta: &Value) -> Vec<String> {
    let member_ids: Vec<&str> = meta["workspace_members"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    meta["packages"]
        .as_array()
        .map(|pkgs| {
            pkgs.iter()
                .filter(|p| p["id"].as_str().is_some_and(|id| member_ids.contains(&id)))
                .filter_map(|p| p["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Packages (name, manifest dir) for workspace members only (external
/// dependencies in `packages` are excluded — `-p`/feature flags only work for
/// workspace members).
fn member_manifests(meta: &Value) -> Vec<(String, PathBuf)> {
    let members = member_names(meta);
    meta["packages"]
        .as_array()
        .map(|pkgs| {
            pkgs.iter()
                .filter(|p| {
                    p["name"]
                        .as_str()
                        .is_some_and(|n| members.iter().any(|m| m == n))
                })
                .filter_map(|p| {
                    let name = p["name"].as_str()?.to_string();
                    let manifest = p["manifest_path"].as_str()?;
                    let dir = PathBuf::from(manifest).parent()?.to_path_buf();
                    Some((name, dir))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Direct reverse dependencies of a package name.
fn reverse_deps(meta: &Value, name: &str) -> Vec<String> {
    meta["packages"]
        .as_array()
        .map(|pkgs| {
            pkgs.iter()
                .filter(|p| {
                    p["dependencies"]
                        .as_array()
                        .is_some_and(|deps| deps.iter().any(|d| d["name"].as_str() == Some(name)))
                })
                .filter_map(|p| p["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Changed files -> owning crates (+ direct reverse deps).
///
/// git 失败一律上抛而不是 `unwrap_or_default()`：变更集为空会被调用方读成
/// "no affected crates changed" 并 **PASS**，那是 fail-open —— 同一缺陷类刚在
/// `code_intel` 侧被独立 Review round 2 堵住（`Repo::porcelain_result()`）。
/// 现在 git 取不到变更集时门记 UNKNOWN 并写明原因。
fn changed_member_names(
    repo: &Repo,
    meta: &Value,
    members: &[String],
) -> Result<Vec<String>, String> {
    let manifests = member_manifests(meta);
    let mut changed: Vec<String> = Vec::new();

    // committed changes vs HEAD
    let tracked = repo
        .git(&["diff", "--name-only", "HEAD"])
        .map_err(|e| format!("git diff HEAD failed, cannot tell what changed: {e}"))?;
    let mut files: Vec<String> = tracked.lines().map(str::to_string).collect();
    // untracked additions
    let status = repo
        .porcelain_result()
        .map_err(|e| format!("git status --porcelain failed, cannot tell what changed: {e}"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("?? ") {
            files.push(rest.to_string());
        }
    }

    for f in &files {
        let abs = repo.root.join(f);
        for (name, dir) in &manifests {
            // 词法比较而非归一化比较：`git diff HEAD` 会列出**已删除**的路径，
            // 那些路径归一化必然失败，用 `path_is_within_resolved` 反而会把删除的
            // crate 从 affected 集合里漏掉（fail-open）。这里不涉及 spawn，安全边界
            // 不在这一层，保留词法判定。
            if path_is_within(&abs, dir) && !changed.iter().any(|c| c == name) {
                changed.push(name.clone());
            }
        }
    }

    // direct reverse dependencies of changed crates
    let mut with_rev = changed.clone();
    for name in &changed {
        for rev in reverse_deps(meta, name) {
            if members.iter().any(|m| m == &rev) && !with_rev.iter().any(|c| c == &rev) {
                with_rev.push(rev);
            }
        }
    }
    with_rev.sort();
    with_rev.dedup();
    Ok(with_rev)
}

/// Light architecture gate: every `crates/*` workspace member must be declared
/// in policies/architecture.toml [[crate]] (apps/engineering are hosts/tooling).
pub fn architecture_gate(config: &Config, _budget: GateBudget) -> Gate {
    let policy = config.policies_dir.join("architecture.toml");
    let text = match std::fs::read_to_string(&policy) {
        Ok(t) => t,
        Err(e) => return Gate::fail("architecture-policy", &format!("read failed: {e}")),
    };
    let v: toml::Value = match toml::from_str(&text) {
        Ok(v) => v,
        Err(e) => return Gate::fail("architecture-policy", &format!("parse failed: {e}")),
    };
    let declared: Vec<String> = v
        .get("crate")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("name").and_then(toml::Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => {
            return Gate::unknown(
                "architecture-policy",
                &format!("cargo metadata failed: {e}"),
            );
        }
    };
    let missing: Vec<String> = member_manifests(&meta)
        .into_iter()
        .filter(|(_, dir)| path_is_within(dir, &config.crates_dir))
        .map(|(name, _)| name)
        .filter(|name| !declared.iter().any(|d| d == name))
        .collect();

    if missing.is_empty() {
        Gate::ok(
            "architecture-policy",
            &format!("{} crates declared", declared.len()),
        )
    } else {
        Gate::fail(
            "architecture-policy",
            &format!(
                "crates/ members missing from architecture.toml: {}",
                missing.join(", ")
            ),
        )
    }
}

/// Light dependency-governance gate: lockfile present + policy parses.
/// Dependency governance: static checks (lockfile + policy parse) AND real
/// cargo-deny execution (advisories / licenses / bans / sources) against
/// policies/deny.toml. cargo-deny missing => UNKNOWN, never a silent PASS.
pub fn dependency_gate(repo: &Repo, config: &Config, budget: GateBudget) -> Gate {
    if !repo.root.join("Cargo.lock").exists() {
        return Gate::fail(
            "dependency-governance",
            "Cargo.lock missing (lockfile_required = true)",
        );
    }
    let policy = config.policies_dir.join("dependencies.toml");
    let text = match std::fs::read_to_string(&policy) {
        Ok(t) => t,
        Err(e) => return Gate::fail("dependency-governance", &format!("read failed: {e}")),
    };
    if let Err(e) = toml::from_str::<toml::Value>(&text) {
        return Gate::fail("dependency-governance", &format!("parse failed: {e}"));
    }
    if !cargo_tool_available(repo, "deny", budget) {
        return Gate::unknown(
            "dependency-governance",
            "static checks passed; cargo-deny not installed (install with: cargo install cargo-deny --locked)",
        );
    }
    let deny_cfg = config.policies_dir.join("deny.toml");
    let secs = budget_secs(budget);
    let out = match run_bounded(
        &repo.root,
        "cargo",
        &[
            "deny",
            "--offline",
            "--config",
            deny_cfg.to_str().unwrap_or("policies/deny.toml"),
            "check",
            "advisories",
            "licenses",
            "bans",
            "sources",
        ],
        budget,
    ) {
        CommandOutcome::Exited { success: true, .. } => {
            return Gate::ok(
                "dependency-governance",
                "cargo-deny: advisories/licenses/bans/sources PASS",
            );
        }
        CommandOutcome::Exited {
            success: false,
            text,
        } => text,
        CommandOutcome::TimedOut { .. } => {
            let mut g = Gate::fail(
                "dependency-governance",
                &format!("gate 'dependency-governance' timed out after {secs}s"),
            );
            g.timed_out = true;
            return g;
        }
        CommandOutcome::SpawnFailed { detail } => {
            return Gate::fail("dependency-governance", &detail);
        }
    };
    let tail: Vec<&str> = out.lines().rev().take(20).collect();
    let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
    Gate::fail(
        "dependency-governance",
        &format!("cargo-deny check FAILED:\n{tail}"),
    )
}

// ---------------------------------------------------------------------------
// Full gates (declared by policies/quality.toml [verification.full]).
// Design rule: a gate with nothing machine-verifiable to run, or whose tooling
// is missing, records UNKNOWN with a reason — never a silent PASS.
// ---------------------------------------------------------------------------

fn rs_files_under(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(rs_files_under(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// True if `cargo <subcmd> --version` succeeds (subcommand installed).
fn cargo_tool_available(repo: &Repo, subcmd: &str, budget: GateBudget) -> bool {
    matches!(
        run_bounded(&repo.root, "cargo", &[subcmd, "--version"], budget),
        CommandOutcome::Exited { success: true, .. }
    )
}

/// Declared Cargo test targets only: helper files are not independent targets.
fn integration_targets(meta: &Value) -> Vec<(String, String)> {
    let mut targets = Vec::new();
    if let (Some(packages), Some(members)) = (
        meta["packages"].as_array(),
        meta["workspace_members"].as_array(),
    ) {
        for package in packages.iter().filter(|p| members.contains(&p["id"])) {
            if let (Some(name), Some(tests)) =
                (package["name"].as_str(), package["targets"].as_array())
            {
                for test in tests {
                    if test["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "test"))
                    {
                        if let Some(test_name) = test["name"].as_str() {
                            targets.push((name.to_string(), test_name.to_string()));
                        }
                    }
                }
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

/// Runs each real target via `cargo test -p <member> --test <name>`.
/// None declared => UNKNOWN.
pub fn integration_gate(repo: &Repo, budget: GateBudget) -> Gate {
    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => return Gate::unknown("integration", &format!("cargo metadata failed: {e}")),
    };
    let targets = integration_targets(&meta);
    if targets.is_empty() {
        return Gate::unknown(
            "integration",
            "no integration test targets declared by cargo metadata",
        );
    }
    let packages = targets
        .iter()
        .map(|(member, _)| member.clone())
        .collect::<Vec<_>>();
    let binaries = match product_binaries(repo, &meta, &packages, "integration", budget) {
        Ok(binaries) => binaries,
        Err(e) => return fail_from("integration", e),
    };
    let mut failures: Vec<String> = Vec::new();
    for (member, test) in &targets {
        let g = cargo_test_gate(
            repo,
            "integration",
            &["test", "-p", member, "--test", test],
            binaries.as_ref(),
            budget,
        );
        if g.verdict == "FAIL" {
            failures.push(format!("{member}::{test}: {}", g.detail));
        }
    }
    if failures.is_empty() {
        Gate::ok(
            "integration",
            &format!("{} integration target(s) passed", targets.len()),
        )
    } else {
        Gate::fail("integration", &failures.join("\n"))
    }
}

/// Coverage summary via cargo-llvm-cov; tool missing or run failure => UNKNOWN.
/// Parses the TOTAL row from the full output (the table can be followed by
/// per-binary test progress lines, so a tail-trimmed capture misses it).
pub fn coverage_gate(repo: &Repo, budget: GateBudget) -> Gate {
    if !cargo_tool_available(repo, "llvm-cov", budget) {
        return Gate::unknown(
            "coverage-summary",
            "cargo-llvm-cov not installed (install with: cargo install cargo-llvm-cov)",
        );
    }
    let secs = budget_secs(budget);
    let out = match run_bounded(
        &repo.root,
        "cargo",
        &["llvm-cov", "--workspace", "--summary-only"],
        budget,
    ) {
        CommandOutcome::Exited {
            success: true,
            text,
        } => text,
        CommandOutcome::Exited {
            success: false,
            text,
        } => {
            return Gate::unknown("coverage-summary", &format!("coverage run failed: {text}"));
        }
        CommandOutcome::TimedOut { .. } => {
            let mut g = Gate::fail(
                "coverage-summary",
                &format!("gate 'coverage-summary' timed out after {secs}s"),
            );
            g.timed_out = true;
            return g;
        }
        CommandOutcome::SpawnFailed { detail } => {
            return Gate::unknown(
                "coverage-summary",
                &format!("coverage run failed: {detail}"),
            );
        }
    };
    let total = out
        .lines()
        .rfind(|l| l.contains("TOTAL") && l.contains('%'))
        .map(str::to_string);
    match total {
        Some(t) => Gate::ok("coverage-summary", &format!("TOTAL: {}", t.trim())),
        None => {
            let n = out.lines().filter(|l| l.contains('%')).count();
            Gate::ok(
                "coverage-summary",
                &format!("coverage summary produced (no TOTAL row; {n} % rows)"),
            )
        }
    }
}

/// Fuzz: cargo-fuzz installed + targets declared. Missing either => UNKNOWN.
pub fn fuzz_gate(repo: &Repo, budget: GateBudget) -> Gate {
    if !cargo_tool_available(repo, "fuzz", budget) {
        return Gate::unknown(
            "selected-fuzz",
            "cargo-fuzz not installed (install with: cargo install cargo-fuzz)",
        );
    }
    if !repo.root.join("fuzz/Cargo.toml").exists() {
        return Gate::unknown(
            "selected-fuzz",
            "no fuzz targets declared (fuzz/Cargo.toml missing)",
        );
    }
    // cargo-fuzz 依赖 libfuzzer 的 nightly `-Z` 选项；显式使用 +nightly 工具链。
    let secs = budget_secs(budget);
    match run_bounded(&repo.root, "cargo", &["+nightly", "fuzz", "check"], budget) {
        CommandOutcome::Exited { success: true, .. } => Gate::ok("selected-fuzz", "ok"),
        CommandOutcome::Exited {
            success: false,
            text,
        } => {
            let tail = text
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            Gate::fail(
                "selected-fuzz",
                if tail.is_empty() {
                    "command failed"
                } else {
                    &tail
                },
            )
        }
        CommandOutcome::TimedOut { .. } => {
            let mut g = Gate::fail(
                "selected-fuzz",
                &format!("gate 'selected-fuzz' timed out after {secs}s"),
            );
            g.timed_out = true;
            g
        }
        CommandOutcome::SpawnFailed { detail } => Gate::fail("selected-fuzz", &detail),
    }
}

/// Concurrency tests under tests/concurrency/; none declared => UNKNOWN.
pub fn concurrency_gate(repo: &Repo, budget: GateBudget) -> Gate {
    let files = rs_files_under(&repo.root.join("tests/concurrency"));
    if files.is_empty() {
        return Gate::unknown(
            "selected-concurrency",
            "no concurrency tests declared under tests/concurrency/",
        );
    }
    let mut failures: Vec<String> = Vec::new();
    for f in &files {
        let stem = f
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let g = cargo_gate(
            repo,
            "selected-concurrency",
            &["test", "--test", &stem],
            budget,
        );
        if g.verdict == "FAIL" {
            failures.push(format!("{stem}: {}", g.detail));
        }
    }
    if failures.is_empty() {
        Gate::ok(
            "selected-concurrency",
            &format!("{} concurrency test(s) passed", files.len()),
        )
    } else {
        Gate::fail("selected-concurrency", &failures.join("\n"))
    }
}

/// Bench gate: run the encrypted-dataplane performance benchmark (P3.6
/// `perf_bench` E4 driver) and map its budget verdict onto the gate.
/// PASS => gate PASS (metrics in detail); WARN => PASS with note (non-blocking);
/// FAIL => gate FAIL (regression blocks); run/parse failure => UNKNOWN (never
/// silently passed). Baseline comparison happens inside the driver
/// (PRODUCT §12.36 / §12.37).
pub fn bench_gate(repo: &Repo, _config: &Config, budget: GateBudget) -> Gate {
    let secs = budget_secs(budget);
    let text = match run_bounded(
        &repo.root,
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "nexus",
            "--example",
            "perf_bench",
            "--",
            "--json",
        ],
        budget,
    ) {
        CommandOutcome::Exited {
            success: true,
            text,
        } => text,
        CommandOutcome::Exited {
            success: false,
            text,
        } => {
            return Gate::unknown(
                "bench",
                &format!("perf_bench run failed (exit != 0): {}", text.trim()),
            );
        }
        CommandOutcome::TimedOut { .. } => {
            let mut g = Gate::fail("bench", &format!("gate 'bench' timed out after {secs}s"));
            g.timed_out = true;
            return g;
        }
        CommandOutcome::SpawnFailed { detail } => {
            return Gate::unknown("bench", &format!("perf_bench run failed: {detail}"));
        }
    };
    bench_verdict_gate(&text)
}

/// Map perf_bench driver output onto a bench Gate (pure; unit-testable).
fn bench_verdict_gate(text: &str) -> Gate {
    // The driver prints exactly one JSON object on stdout; take the last
    // brace-delimited line in case cargo merged build notes into stderr.
    let line = text.lines().rev().find(|l| l.trim_start().starts_with('{'));
    let Some(line) = line else {
        return Gate::unknown("bench", "perf_bench produced no JSON output");
    };
    let v: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            return Gate::unknown("bench", &format!("perf_bench JSON parse failed: {e}"));
        }
    };
    let verdict = v
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("FAIL")
        .to_string();
    let metric = |path: &str| -> f64 { v.pointer(path).and_then(|x| x.as_f64()).unwrap_or(0.0) };
    let detail = format!(
        "aead {:.1} MB/s ({:.2}us/frame) / tunnel {:.1} MB/s ({:.2}us rtt); budget verdict: {}",
        metric("/aead/throughput_mbps"),
        metric("/aead/frame_roundtrip_us"),
        metric("/tunnel/throughput_mbps"),
        metric("/tunnel/roundtrip_us"),
        verdict,
    );
    match verdict.as_str() {
        "PASS" => Gate::ok("bench", &detail),
        "WARN" => Gate::ok("bench", &format!("{detail} (WARN: non-blocking)")),
        "FAIL" => Gate::fail("bench", &detail),
        other => Gate::unknown("bench", &format!("{detail} (unexpected verdict: {other}")),
    }
}

/// Performance budgets: require machine-readable thresholds in
/// policies/quality.toml [performance]; absent => UNKNOWN (no budget to check).
pub fn performance_budgets_gate(config: &Config, _budget: GateBudget) -> Gate {
    let Some(perf) = config.quality.get("performance") else {
        return Gate::unknown(
            "performance-budgets",
            "no [performance] section in policies/quality.toml (baseline/noise tolerance/warning/blocking thresholds required per AGENTS.md)",
        );
    };
    let keys: Vec<String> = perf
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    if keys.iter().any(|k| k == "baseline") && keys.iter().any(|k| k == "blocking") {
        Gate::ok(
            "performance-budgets",
            &format!("budgets defined: {}", keys.join(", ")),
        )
    } else {
        Gate::unknown(
            "performance-budgets",
            &format!(
                "[performance] section incomplete (baseline + blocking required); found: {}",
                if keys.is_empty() {
                    "<none>".to_string()
                } else {
                    keys.join(", ")
                }
            ),
        )
    }
}

/// Platform checks: portable-core crates must be free of platform-specific
/// dependencies (target-specific tables or known OS-only crates).
pub fn platform_checks_gate(config: &Config, _budget: GateBudget) -> Gate {
    const PLATFORM_CRATES: &[&str] = &[
        "winapi",
        "windows-sys",
        "windows",
        "libc",
        "nix",
        "objc",
        "core-foundation",
        "security-framework",
        "io-kit-sys",
    ];
    let mut violations: Vec<String> = Vec::new();
    for name in &config.portable_core {
        let manifest = config.crates_dir.join(name).join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            violations.push(format!(
                "{name}: manifest missing at {}",
                manifest.display()
            ));
            continue;
        };
        let Ok(v) = toml::from_str::<toml::Value>(&text) else {
            violations.push(format!("{name}: manifest unparseable"));
            continue;
        };
        if v.get("target").is_some() {
            violations.push(format!("{name}: [target.'cfg(...)'.dependencies] present"));
        }
        let deps = v.get("dependencies").and_then(toml::Value::as_table);
        for dep in deps.unwrap_or(&toml::map::Map::new()).keys() {
            let bare = dep.split('.').next().unwrap_or(dep);
            if PLATFORM_CRATES.contains(&bare) {
                violations.push(format!("{name}: platform-specific dependency '{dep}'"));
            }
        }
    }
    if violations.is_empty() {
        Gate::ok(
            "platform-checks",
            &format!(
                "{} portable-core crate(s) free of platform-specific dependencies",
                config.portable_core.len()
            ),
        )
    } else {
        Gate::fail("platform-checks", &violations.join("\n"))
    }
}

/// Feature matrix: for each workspace member, `cargo check` with
/// --no-default-features and --all-features (per quality.toml [features]).
pub fn feature_matrix_gate(repo: &Repo, budget: GateBudget) -> Gate {
    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => return Gate::unknown("feature-matrix", &format!("cargo metadata failed: {e}")),
    };
    let mut names: Vec<String> = member_manifests(&meta)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    names.sort();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for name in &names {
        for flag in ["--no-default-features", "--all-features"] {
            let g = cargo_gate(repo, "feature-matrix", &["check", "-p", name, flag], budget);
            checked += 1;
            if g.verdict == "FAIL" {
                failures.push(format!("{name} {flag}: {}", g.detail));
            }
        }
    }
    if failures.is_empty() {
        Gate::ok(
            "feature-matrix",
            &format!("{checked} member×feature checks passed ({})", names.len()),
        )
    } else {
        Gate::fail("feature-matrix", &failures.join("\n"))
    }
}

/// Portable core: every harness.toml [portable_core] crate must compile for
/// wasm32-wasip1; target not installed => UNKNOWN.
pub fn portable_core_gate(repo: &Repo, config: &Config, budget: GateBudget) -> Gate {
    // 必须用全量输出：`rustup target list --installed` 在装了很多 target 的
    // 机器上超过 12 行，run_at 的 tail 会把 wasm32-wasip1 截掉，导致"已安装"
    // 被误判为缺失（UNKNOWN）。
    let installed = match run_bounded(
        &repo.root,
        "rustup",
        &["target", "list", "--installed"],
        budget,
    ) {
        CommandOutcome::Exited {
            success: true,
            text,
        } => text,
        _ => String::new(),
    };
    if !installed.contains("wasm32-wasip1") {
        return Gate::unknown(
            "portable-core",
            "wasm32-wasip1 target not installed (install with: rustup target add wasm32-wasip1)",
        );
    }
    let mut failures: Vec<String> = Vec::new();
    for name in &config.portable_core {
        let g = cargo_gate(
            repo,
            "portable-core",
            &["check", "-p", name, "--target", "wasm32-wasip1"],
            budget,
        );
        if g.verdict == "FAIL" {
            failures.push(format!("{name}: {}", g.detail));
        }
    }
    if failures.is_empty() {
        Gate::ok(
            "portable-core",
            &format!(
                "{} portable crate(s) compile for wasm32-wasip1",
                config.portable_core.len()
            ),
        )
    } else {
        Gate::fail("portable-core", &failures.join("\n"))
    }
}

/// 未实现 gate 的兜底判定（契约 §4.4）：记 UNKNOWN 并带原因，绝不静默 PASS。
///
/// 现状（2026-10-16 e2e-contract-schema 逐个复核）：`policies/quality.toml`
/// 声明的全部 gate（fast 8 个 + full 14 个）都已在 `commands.rs` 的 verify()
/// match 中路由到本文件的确定性实现，没有声明落在此兜底上。其中依赖外部
/// 工具/真机、工具缺失时必须保持 UNKNOWN 的 gate，在各自函数体内已带具体
/// 原因（而非空泛 TODO）：
/// - coverage-summary：需 cargo-llvm-cov（`coverage_gate`）；
/// - selected-fuzz：需 cargo-fuzz 且声明 `fuzz/Cargo.toml`（`fuzz_gate`）；
/// - portable-core：需 `rustup target add wasm32-wasip1`（`portable_core_gate`）；
/// - dependency-governance：静态检查之外的真跑需 cargo-deny（`dependency_gate`）；
/// - performance-budgets：需 quality.toml `[performance]` 的 baseline+blocking
///   完整阈值（`performance_budgets_gate`）；
/// - integration：cargo metadata 未声明任何 integration 目标（`integration_gate`）。
///
/// 因此本函数只在"quality.toml 新增了未路由的 gate 声明"时触发——那是契约
/// 与实现的脱耦；正确处置是在 commands.rs 补路由，而不是放行。
pub fn unimplemented(name: &str) -> Gate {
    Gate::unknown(
        name,
        "gate not implemented in MVP harness (recorded UNKNOWN, not silently passed)",
    )
}

// ---------------------------------------------------------------------------
// N2 资源类型中立门禁（P0-6，完成标志 #6；综合规划 D5 bunny 架构门禁）
// ---------------------------------------------------------------------------

/// 词边界感知：`hay` 中是否出现 `prefix::Variant` 且其后不是标识符字符
///（避免 `Self::ComputeJobRejected` 误命中 `Self::Compute`）。
fn contains_variant_ref(hay: &str, prefix: &str, variant: &str) -> bool {
    let needle = format!("{prefix}::{variant}");
    let mut start = 0;
    while let Some(pos) = hay[start..].find(&needle) {
        let end = start + pos + needle.len();
        let next = hay[end..].chars().next();
        if !next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
        start = end;
    }
    false
}

/// 剥离行注释/块注释/字符串字面量，返回代码部分。
///
/// Rust 块注释可嵌套；字符串含转义；raw string 支持 `r"..."` / `r#"..."#` /
/// `r##"..."##`；字符字面量 `'c'` / `'\n'` 按字面量跳过（其余 `'` 如生命周期
/// 不影响判定——`'` 内不可能出现 `//` 或变体引用）。
/// 这是策略扫描器不是解析器：极限情况可能误判，误判走 allow 列表显式声明。
fn strip_line_code(line: &str, block_depth: &mut usize) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if *block_depth > 0 {
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                *block_depth += 1;
                i += 2;
            } else if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *block_depth -= 1;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        let b = bytes[i];
        // 行注释。
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            break;
        }
        // 块注释开始。
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            *block_depth = 1;
            i += 2;
            continue;
        }
        // raw string：r"..." / r#"..."# / r##"..."##。
        if b == b'r' {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let closer: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let mut k = j;
                let mut found = false;
                while k + closer.len() <= bytes.len() {
                    if &bytes[k..k + closer.len()] == closer.as_slice() {
                        found = true;
                        break;
                    }
                    k += 1;
                }
                i = if found { k + closer.len() } else { bytes.len() };
                continue;
            }
        }
        // 普通字符串 / 字节字符串。
        if b == b'"' || (b == b'b' && i + 1 < bytes.len() && bytes[i + 1] == b'"') {
            if b == b'b' {
                i += 1;
            }
            i += 1; // 跳过开引号
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // 字符字面量 'c' / '\n'（两格或转义四格形式）。
        if b == b'\'' {
            let is_char_lit = (i + 2 < bytes.len() && bytes[i + 2] == b'\'')
                || (i + 3 < bytes.len() && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\'');
            if is_char_lit {
                i += if bytes[i + 1] == b'\\' { 4 } else { 3 };
                continue;
            }
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// 单行判定（纯函数，可单测）：剥离注释/字符串后的代码行是否为
/// "资源类型专属分支"——同时含变体引用与分支 token。
///
/// N2 P1-6：判定输入是**逻辑行**（跨行拼接后的整条语句），不是物理行——
/// `matches!(kind,\n ResourceKind::Service)` 与 `if let Some(x) = ...\n { k == ResourceKind::Service }`
/// 按物理行逐行判定会漏掉（`matches!` 与变体引用不在同一行）。
fn is_specialized_branch(code_line: &str, variants: &[String]) -> bool {
    let has_variant = variants.iter().any(|var| {
        contains_variant_ref(code_line, "ResourceKind", var)
            || contains_variant_ref(code_line, "Self", var)
    });
    if !has_variant {
        return false;
    }
    code_line.contains("=>")
        || code_line.contains("matches!")
        || ((code_line.contains("if ") || code_line.contains("while "))
            && (code_line.contains("==") || code_line.contains("!=")))
}

/// 逻辑行聚合：把跨行的 Rust 语句拼成一条（括号/花括号未闭合则继续拼接）。
///
/// N1-p03 回归：原实现逐物理行判定，`matches!(kind,\n ResourceKind::Service)`
/// 这类写法两个 token 分处两行 → 判定漏掉（门禁可被绕过）。这里按分隔符配平
/// 把语句拼起来再判定。上限 `MAX_LOGICAL_LINE` 防病态输入。
const MAX_LOGICAL_LINE: usize = 8 * 1024;

/// 语句分隔符增量表（成对闭合；只统计代码部分，字符串/注释已在剥离时处理）。
fn logical_line_balance(fragment: &str) -> i64 {
    let mut depth = 0i64;
    for c in fragment.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// 一个逻辑行覆盖的物理行区间（1-based，闭区间）。
///
/// 变体引用与分支 token 可能分处区间内不同行（`matches!(kind,` +
/// `ResourceKind::Service)`），因此 allow 的行号匹配按**区间**判定，
/// 而不是只看起始行。
type LineSpan = (usize, usize);

/// 把已剥离注释/字符串的代码行聚合为逻辑行（纯函数，可单测）。
///
/// 切分规则（N2 P1-6）：一行在"语句结束"时切出——以 `;` / `}` 收尾，或以
/// `,` / `{` 收尾且该行没有打开新的括号层。分号行立即切出，因此行号归属与
/// 物理行一致（allow 才能钉到行号）；只有"未闭合的跨行语句"（如
/// `matches!(kind,`）才会与后续行拼接——那正是原实现漏判的形态。
///
/// 返回 `(行区间, 拼接后的代码)`。
fn logical_lines<'a>(code_lines: impl IntoIterator<Item = &'a str>) -> Vec<(LineSpan, String)> {
    let mut out: Vec<(LineSpan, String)> = Vec::new();
    let mut start_line = 0usize;
    let mut buffer = String::new();
    for (idx, line) in code_lines.into_iter().enumerate() {
        let trimmed = line.trim();
        if buffer.is_empty() {
            if trimmed.is_empty() {
                continue;
            }
            start_line = idx + 1;
        } else {
            buffer.push(' ');
        }
        buffer.push_str(trimmed);
        // F1 fix: balance must be computed on the accumulated buffer, not the
        // current physical line. Otherwise rustfmt's one-arg-per-line style
        // (e.g. `matches!(\n kind,\n ResourceKind::Service,\n);`) gets split
        // into separate logical lines, and the `matches!`/variant pairing is
        // never seen together -> bypass.
        let closes = logical_line_balance(&buffer) <= 0;
        let ends = trimmed.ends_with(';')
            || trimmed.ends_with('}')
            || (closes && (trimmed.ends_with(',') || trimmed.ends_with('{')));
        if ends || buffer.len() > MAX_LOGICAL_LINE {
            out.push(((start_line, idx + 1), std::mem::take(&mut buffer)));
        }
    }
    if !buffer.is_empty() {
        out.push(((start_line, usize::MAX), buffer));
    }
    out
}

/// 允许条目（`file` ＋ 精确 `line` ＋ `contains`；N2 P1-6）。
///
/// `line` 必填——只有"文件＋子串"的 allow 会静默放行同一文件里新增的同子串
/// 行为分叉（例如在 `Self::Service =>` 旁边再加一个 `Self::Service =>` 分支）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowEntry {
    file: String,
    line: usize,
    contains: String,
}

/// 判定某条违规是否被 allow 覆盖（行号落在逻辑行区间内 ＋ 内容匹配）。
fn allow_covers(allow: &[AllowEntry], file: &str, span: LineSpan, code: &str) -> bool {
    allow.iter().any(|a| {
        a.file == file && a.line >= span.0 && a.line <= span.1 && code.contains(&a.contains)
    })
}

/// N2 资源类型中立门禁（P0-6，完成标志 #6；N2 P1-5/P1-6）。
///
/// 扫描 `policies/architecture.toml [resource_kind_neutrality]` 声明的 crate 的
/// `src/**/*.rs`；flag 同时含"变体引用"（`ResourceKind::V` / `Self::V`，词边界）
/// 与"分支 token"（`=>` / `matches!` / `if`+`==`/`!=`）的**逻辑行**；命中 allow
/// 列表（精确到行号）的除外。
///
/// fail-closed：policy 缺失/字段缺失 → FAIL；**crate 目录不存在或零 `.rs`
/// 文件 → FAIL**（P1-6：写错 crate 名曾得到"4 crate(s), 0 file(s): PASS"）。
pub fn resource_kind_neutrality_gate(config: &Config, _budget: GateBudget) -> Gate {
    const GATE: &str = "resource-type-neutrality";
    let policy = config.policies_dir.join("architecture.toml");
    let text = match std::fs::read_to_string(&policy) {
        Ok(t) => t,
        Err(e) => return Gate::fail(GATE, &format!("read failed: {e}")),
    };
    let v: toml::Value = match toml::from_str(&text) {
        Ok(v) => v,
        Err(e) => return Gate::fail(GATE, &format!("parse failed: {e}")),
    };
    let section = match v.get("resource_kind_neutrality") {
        Some(s) => s,
        None => {
            return Gate::fail(
                GATE,
                "missing [resource_kind_neutrality] in policies/architecture.toml (fail-closed)",
            );
        }
    };
    let str_list = |key: &str| -> Vec<String> {
        section
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let crates = str_list("crates");
    let variants = str_list("variants");
    if crates.is_empty() || variants.is_empty() {
        return Gate::fail(
            GATE,
            "[resource_kind_neutrality] must declare non-empty crates + variants (fail-closed)",
        );
    }
    let mut allow_errors: Vec<String> = Vec::new();
    let allows: Vec<AllowEntry> = section
        .get("allow")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let file = e.get("file")?.as_str()?.to_string();
                    let contains = e.get("contains")?.as_str()?.to_string();
                    // P1-6：`line` 必填（缺失即 fail-closed）。
                    let Some(line) = e.get("line").and_then(toml::Value::as_integer) else {
                        allow_errors.push(format!(
                            "allow entry for {file} ({contains}) is missing 'line'; sub-string-only allow silently permits new branches (P1-6)"
                        ));
                        return None;
                    };
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    Some(AllowEntry {
                        file,
                        line: line as usize,
                        contains,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if !allow_errors.is_empty() {
        return Gate::fail(
            GATE,
            &format!(
                "allow list invalid (fail-closed):\n{}",
                allow_errors.join("\n")
            ),
        );
    }
    let repo_root = config.policies_dir.parent().unwrap_or(&config.policies_dir);

    let mut violations: Vec<String> = Vec::new();
    let mut missing_crates: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;
    for krate in &crates {
        let src_dir = config.crates_dir.join(krate).join("src");
        let files = rs_files_under(&src_dir);
        // P1-6：crate 名写错 / 目录缺失 → FAIL，绝不"0 file(s): PASS"。
        if files.is_empty() {
            missing_crates.push(format!("{krate} (no .rs under {})", src_dir.display()));
            continue;
        }
        for f in files {
            scanned_files += 1;
            let text = match std::fs::read_to_string(&f) {
                Ok(t) => t,
                Err(e) => {
                    violations.push(format!("{}: read failed: {e}", f.display()));
                    continue;
                }
            };
            let rel = f
                .strip_prefix(repo_root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| f.display().to_string());
            let mut block_depth = 0usize;
            let stripped: Vec<String> = text
                .lines()
                .map(|line| strip_line_code(line, &mut block_depth))
                .collect();
            for (span, logical) in logical_lines(stripped.iter().map(String::as_str)) {
                if !is_specialized_branch(&logical, &variants) {
                    continue;
                }
                if allow_covers(&allows, &rel, span, &logical) {
                    continue;
                }
                let where_ = if span.0 == span.1 {
                    format!("{}", span.0)
                } else {
                    format!("{}-{}", span.0, span.1)
                };
                violations.push(format!("{rel}:{where_}: {logical}"));
            }
        }
    }
    if !missing_crates.is_empty() {
        return Gate::fail(
            GATE,
            &format!(
                "fail-closed: declared crate(s) have no scannable src/**/*.rs: {}",
                missing_crates.join(", ")
            ),
        );
    }
    if violations.is_empty() {
        Gate::ok(
            GATE,
            &format!(
                "{} crate(s) [{crates:?}], {scanned_files} file(s): no resource-type-specialized branches",
                crates.len()
            ),
        )
    } else {
        Gate::fail(
            GATE,
            &format!(
                "{} violation(s):\n{}",
                violations.len(),
                violations.join("\n")
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_targets_include_declared_names_and_exclude_helpers_and_dependencies() {
        let meta = serde_json::json!({"workspace_members":["workspace"], "packages":[
            {"id":"workspace","name":"fixture", "targets":[
                {"name":"declared-custom-name","kind":["test"],"src_path":"tests/nested/entry.rs"},
                {"name":"lib","kind":["lib"]},
                {"name":"example","kind":["example"]}]},
            {"id":"dependency","name":"external", "targets":[{"name":"external-test","kind":["test"]}]}]});
        assert_eq!(
            integration_targets(&meta),
            vec![("fixture".into(), "declared-custom-name".into())]
        );
        assert!(integration_targets(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn binary_artifacts_require_current_workspace_non_test_complete_unambiguous_files() {
        let root = std::env::temp_dir().join(format!("n37-artifacts-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo { root: root.clone() };
        let meta = serde_json::json!({"workspace_members":["cli-id","daemon-id"], "packages":[
            {"name":"nexus","id":"cli-id"},{"name":"nexusd","id":"daemon-id"}]});
        for name in ["nexus", "nexusd"] {
            std::fs::write(root.join(name), "artifact fixture").unwrap();
        }
        let artifact = |id: &str, name: &str| {
            serde_json::json!({"reason":"compiler-artifact",
            "package_id":id, "target":{"name":name,"kind":["bin"]}, "profile":{"test":false}, "executable":name})
        };
        let cli = artifact("cli-id", "nexus");
        let daemon = artifact("daemon-id", "nexusd");
        let parse = |values: &[Value]| {
            binaries_from_artifacts(
                &repo,
                &meta,
                values
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
                    .as_bytes(),
            )
        };
        let bins = parse(&[cli.clone(), daemon.clone()]).unwrap();
        assert_eq!(bins.cli, root.join("nexus"));
        assert_eq!(bins.daemon, root.join("nexusd"));
        assert!(parse(std::slice::from_ref(&cli)).is_err());
        assert!(parse(&[artifact("foreign", "nexus"), daemon.clone()]).is_err());
        let mut test = cli.clone();
        test["profile"]["test"] = Value::Bool(true);
        assert!(parse(&[test, daemon.clone()]).is_err());
        assert!(parse(&[cli.clone(), cli.clone(), daemon.clone()]).is_err());
        assert!(binaries_from_artifacts(&repo, &meta, b"malformed JSON").is_err());
        std::fs::remove_file(root.join("nexusd")).unwrap();
        assert!(parse(&[cli, daemon]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn member_manifests_only_contains_workspace_members() {
        let meta = cargo_metadata().expect("cargo metadata must run");
        let names: Vec<String> = member_manifests(&meta)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let declared = member_names(&meta);
        assert!(
            names.len() >= 20,
            "expected >= 20 workspace members, found {}",
            names.len()
        );
        assert!(names.iter().all(|n| declared.contains(n)));
        assert!(!names.iter().any(|n| n == "serde_json" || n == "syn"));
    }

    #[test]
    fn dependency_gate_runs_cargo_deny_when_available() {
        let repo = Repo::discover().expect("repo must be discoverable");
        let config = Config::load(&repo).expect("config must load from harness.toml");
        let g = dependency_gate(&repo, &config, GateBudget::unlimited());
        assert_ne!(g.verdict, "FAIL", "dependency gate failed: {}", g.detail);
        if cargo_tool_available(&repo, "deny", GateBudget::unlimited()) {
            assert_eq!(
                g.verdict, "PASS",
                "cargo-deny installed but gate not PASS: {}",
                g.detail
            );
        }
    }

    #[test]
    fn bench_verdict_gate_maps_budget_verdicts() {
        let pass = r#"{"verdict":"PASS","aead":{"frame_roundtrip_us":3.5,"throughput_mbps":600.0},"tunnel":{"throughput_mbps":60.0,"roundtrip_us":11.5}}"#;
        let g = bench_verdict_gate(pass);
        assert_eq!(g.verdict, "PASS");
        assert!(g.detail.contains("600.0 MB/s"));
        assert!(g.detail.contains("60.0 MB/s"));

        let warn = r#"{"verdict":"WARN","aead":{"frame_roundtrip_us":3.5,"throughput_mbps":300.0},"tunnel":{"throughput_mbps":60.0,"roundtrip_us":11.5},"budget":{"warns":["aead_throughput 0.5x"]}}"#;
        let g = bench_verdict_gate(warn);
        assert_eq!(g.verdict, "PASS", "WARN must be non-blocking: {}", g.detail);
        assert!(g.detail.contains("WARN: non-blocking"));

        let fail = r#"{"verdict":"FAIL","aead":{"frame_roundtrip_us":3.5,"throughput_mbps":0.2},"tunnel":{"throughput_mbps":60.0,"roundtrip_us":11.5},"budget":{"fails":["aead_throughput_below_abs_min"]}}"#;
        let g = bench_verdict_gate(fail);
        assert_eq!(g.verdict, "FAIL");

        let empty = "cargo: warning: nothing here";
        let g = bench_verdict_gate(empty);
        assert_eq!(
            g.verdict, "UNKNOWN",
            "no JSON output must not pass silently"
        );

        let bad = "not json at all {";
        let g = bench_verdict_gate(bad);
        assert_eq!(
            g.verdict, "UNKNOWN",
            "unparseable output must not pass silently"
        );
    }

    // --- resource-type-neutrality (P0-6) ---------------------------------

    #[test]
    fn variant_ref_needs_word_boundary() {
        // `Self::ComputeJobRejected` 不得误命中 `Self::Compute`。
        assert!(contains_variant_ref(
            "Self::Compute => x",
            "Self",
            "Compute"
        ));
        assert!(!contains_variant_ref(
            "Self::ComputeJobRejected { .. } => x",
            "Self",
            "Compute"
        ));
        assert!(contains_variant_ref(
            "if k == ResourceKind::Service {",
            "ResourceKind",
            "Service"
        ));
        assert!(!contains_variant_ref(
            "let k = ResourceKind::Services;",
            "ResourceKind",
            "Service"
        ));
    }

    #[test]
    fn strip_line_code_removes_comments_and_strings() {
        let mut depth = 0usize;
        // 行注释里的变体引用必须剥离。
        assert_eq!(
            strip_line_code("let x = 1; // ResourceKind::Service => foo", &mut depth).trim(),
            "let x = 1;"
        );
        // 字符串里的 `=>` 与变体引用必须剥离。
        let code = strip_line_code(r#"format!("ResourceKind::Service => {}", 1)"#, &mut depth);
        assert!(!code.contains("ResourceKind"), "{code}");
        // 块注释（含多行）剥离。
        let a = strip_line_code("/* ResourceKind::Service =>", &mut depth);
        assert_eq!(depth, 1);
        assert!(a.trim().is_empty());
        let b = strip_line_code(
            "still comment */ let y = ResourceKind::Service;",
            &mut depth,
        );
        assert_eq!(depth, 0);
        assert!(b.contains("ResourceKind::Service"), "{b}");
    }

    #[test]
    fn is_specialized_branch_positive_and_negative() {
        let variants: Vec<String> = ["Network", "Service", "Workspace", "Compute", "Device"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // 正：match 分支 / 条件 / matches! 宏。
        assert!(is_specialized_branch(
            "ResourceKind::Service => do_svc(),",
            &variants
        ));
        assert!(is_specialized_branch(
            "if kind == ResourceKind::Network {",
            &variants
        ));
        assert!(is_specialized_branch(
            "matches!(kind, Self::Device)",
            &variants
        ));
        assert!(is_specialized_branch(
            "ResourceKind::Service | ResourceKind::Compute => x,",
            &variants
        ));
        // 负：纯构造（非分支）、规范序列化调用、前缀陷阱。
        assert!(!is_specialized_branch(
            "let k = ResourceKind::Service;",
            &variants
        ));
        assert!(!is_specialized_branch(
            "assert_eq!(ResourceKind::Service.as_str(), \"service\");",
            &variants
        ));
        assert!(!is_specialized_branch(
            "Self::ComputeJobRejected { .. } => abort,",
            &variants
        ));
        assert!(!is_specialized_branch("let x = 1;", &variants));
    }

    #[test]
    fn resource_kind_neutrality_gate_passes_on_current_tree() {
        // 当前契约四 crate 无资源类型专属分支（仅 as_str 规范序列化，已 allow）。
        let repo = crate::env::Repo::discover().expect("repo must be discoverable");
        let config = crate::config::Config::load(&repo).expect("config must load");
        let g = resource_kind_neutrality_gate(&config, GateBudget::unlimited());
        assert_eq!(g.verdict, "PASS", "gate failed: {}", g.detail);
        // P1-5：断言具体 crate 名（只验数量＝侥幸通过）。
        for expected in [
            "nexus-registry",
            "nexus-planner",
            "nexus-session",
            "nexus-auth",
        ] {
            assert!(
                g.detail.contains(expected),
                "gate must prove coverage of {expected}: {}",
                g.detail
            );
        }
        assert!(!g.detail.contains("0 file(s)"), "{}", g.detail);
    }

    /// P1-5：`policies/architecture.toml` 的 crate 集合必须与
    /// `PRODUCT.md` §16.4-6 字面列出的"四 crate"一致（policy↔契约同源）。
    #[test]
    fn policy_crates_match_product_contract() {
        let repo = Repo::discover().expect("repo must be discoverable");
        let config = Config::load(&repo).expect("config must load");
        let text = std::fs::read_to_string(config.policies_dir.join("architecture.toml")).unwrap();
        let v: toml::Value = toml::from_str(&text).expect("architecture.toml parses");
        let policy_crates: Vec<String> = v["resource_kind_neutrality"]["crates"]
            .as_array()
            .expect("crates declared")
            .iter()
            .map(|x| x.as_str().expect("crate is string").to_string())
            .collect();

        let product = std::fs::read_to_string(repo.resolve("PRODUCT.md")).unwrap();
        let at = product
            .find("四 crate 架构门禁通过")
            .expect("PRODUCT.md §16.4-6 anchor present");
        let seg = &product[at..];
        let end = seg
            .find("源码零资源类型专属分支")
            .expect("PRODUCT.md §16.4-6 end anchor present");
        let contract: Vec<String> = seg[..end]
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|s| s.starts_with("nexus-"))
            .map(str::to_string)
            .collect();

        assert_eq!(
            policy_crates, contract,
            "policy crates must equal the PRODUCT.md §16.4-6 contract set"
        );
        assert_eq!(contract.len(), 4, "contract says exactly four crates");
    }

    // --- N2 P1-6：已知绕过样例必须被 flag（元测试） ---

    /// 判定"逻辑行"上的分支（复用门禁内网，纯函数）。
    fn flagged(lines: &[&str], variants: &[String]) -> Vec<String> {
        logical_lines(lines.iter().copied())
            .into_iter()
            .filter(|(_, l)| is_specialized_branch(l, variants))
            .map(|(span, l)| format!("{}-{}: {l}", span.0, span.1))
            .collect()
    }

    fn n2_variants() -> Vec<String> {
        ["Network", "Service", "Workspace", "Compute", "Device"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn known_bypass_samples_are_flagged() {
        // 元测试（P1-6）：这些写法在"逐物理行"实现下全部漏过，逻辑行实现必须 flag。
        let variants = n2_variants();
        let bypasses: Vec<Vec<&str>> = vec![
            // `matches!` 与变体引用分处两行。
            vec!["let b = matches!(kind,", "    ResourceKind::Service);"],
            // match 分支跨行。
            vec![
                "match kind {",
                "    ResourceKind::Compute => do_it(),",
                "    _ => {}",
                "}",
            ],
            // `if` 条件跨行。
            vec!["if kind", "    == ResourceKind::Network", "{ do_it(); }"],
            // 同一文件新增的第二条同子串分支（非 allow 行）。
            vec!["        Self::Service => \"other\","],
            // F1: rustfmt 逐行参数风格（每行一个参数）。
            vec![
                "let b = matches!(",
                "    kind,",
                "    ResourceKind::Service,",
                ");",
            ],
        ];
        for sample in bypasses {
            assert!(
                !flagged(&sample, &variants).is_empty(),
                "bypass sample must be flagged: {sample:?}"
            );
        }
    }

    #[test]
    fn logical_lines_join_and_report_physical_span() {
        let joined = logical_lines([
            "fn f() {",
            "    match kind {",
            "        ResourceKind::Service => 1,",
            "        _ => 0,",
            "    }",
            "}",
        ]);
        // 含变体引用 + `=>` 的逻辑行，区间覆盖第 3 行（allow 行号按区间匹配）。
        assert!(
            joined.iter().any(|(span, l)| span.0 <= 3
                && span.1 >= 3
                && l.contains("ResourceKind::Service")
                && l.contains("=>")),
            "{joined:?}"
        );
        // 分号行立即切出：区间就是它自己（行号归属与物理行一致）。
        let single = logical_lines(["let k = ResourceKind::Service;"]);
        assert_eq!(single[0].0, (1, 1));
        assert!(!is_specialized_branch(&single[0].1, &n2_variants()));
    }

    #[test]
    fn allow_entries_must_be_line_pinned() {
        // P1-6：allow 精确到行号——同一文件里新增的同子串分支不会被放行。
        let allow = [AllowEntry {
            file: "a.rs".into(),
            line: 10,
            contains: "Self::Service =>".into(),
        }];
        assert!(allow_covers(
            &allow,
            "a.rs",
            (10, 10),
            "Self::Service => \"svc\","
        ));
        // 区间内（含）→ 覆盖：变体引用所在行在逻辑行区间内。
        assert!(allow_covers(
            &allow,
            "a.rs",
            (8, 10),
            "match self { Self::Service => \"svc\","
        ));
        // 行号在区间外 → 不覆盖（新增的第二条分支会 flag）。
        assert!(!allow_covers(
            &allow,
            "a.rs",
            (11, 11),
            "Self::Service => \"svc\","
        ));
        // 文件不同 → 不覆盖。
        assert!(!allow_covers(
            &allow,
            "b.rs",
            (10, 10),
            "Self::Service => \"svc\","
        ));
    }

    #[test]
    fn gate_fails_closed_when_declared_crate_dir_missing() {
        // P1-6：crate 名写错 → "0 file(s): PASS" 是伪 fail-closed。构造一个指向
        // 不存在 crate 的 policy，gate 必须 FAIL。
        let repo = crate::env::Repo::discover().expect("repo must be discoverable");
        let config = crate::config::Config::load(&repo).expect("config must load");
        let tmp = std::env::temp_dir().join(format!("harness-rkn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let policy = tmp.join("architecture.toml");
        std::fs::write(
            &policy,
            "[resource_kind_neutrality]\n\
             crates = [\"nexus-registry\", \"nexus-planner\", \"nexus-session\", \"nexus-auth\", \"nexus-typo\"]\n\
             variants = [\"Network\", \"Service\", \"Workspace\", \"Compute\", \"Device\"]\n",
        )
        .unwrap();
        let cfg = crate::config::Config {
            policies_dir: tmp.clone(),
            ..config
        };
        let g = resource_kind_neutrality_gate(&cfg, GateBudget::unlimited());
        assert_eq!(
            g.verdict, "FAIL",
            "missing crate dir must fail: {}",
            g.detail
        );
        assert!(g.detail.contains("nexus-typo"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_fails_closed_when_allow_entry_has_no_line() {
        // P1-6：allow 条目缺 `line` → fail-closed（不再"文件＋子串"宽放行）。
        let repo = crate::env::Repo::discover().expect("repo must be discoverable");
        let config = crate::config::Config::load(&repo).expect("config must load");
        let tmp = std::env::temp_dir().join(format!("harness-rkn-allow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("architecture.toml"),
            "[resource_kind_neutrality]\n\
             crates = [\"nexus-registry\", \"nexus-planner\", \"nexus-session\", \"nexus-auth\"]\n\
             variants = [\"Network\", \"Service\", \"Workspace\", \"Compute\", \"Device\"]\n\
             [[resource_kind_neutrality.allow]]\n\
             file = \"crates/nexus-domain/src/lib.rs\"\n\
             contains = \"Self::Service =>\"\n",
        )
        .unwrap();
        let cfg = crate::config::Config {
            policies_dir: tmp.clone(),
            ..config
        };
        let g = resource_kind_neutrality_gate(&cfg, GateBudget::unlimited());
        assert_eq!(g.verdict, "FAIL", "{}", g.detail);
        assert!(g.detail.contains("missing 'line'"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // --- N2 P1-7：PRODUCT §16 契约 hash 必须可复现 ---

    #[test]
    fn product_section16_contract_hash_is_reproducible() {
        // P1-7 回归：文档里的 hash 值与"自 `## 16.` 至 hash 行之前、按 `\\n` 连接
        // 并补一个换行"的算法不一致——冻结边界防篡改机制形同虚设。
        // §12.58 声明了同一算法且可复现，用它做算法基准。
        let repo = crate::env::Repo::discover().expect("repo must be discoverable");
        let text = std::fs::read_to_string(repo.root.join("PRODUCT.md")).expect("PRODUCT.md");
        // 冻结边界的 hash 必须与"git 里那份 blob"对齐，而不是与某个宿主的 checkout
        // 字节对齐：`.gitattributes` 的 `* text=auto` 会在 Windows 工作树里把 LF 换成
        // CRLF，于是同一 commit 在 Windows 上算出的 hash 与文档里存的值不同——这个
        // 防篡改检查在本就无可篡改的宿主上假红（实测：Windows 109 项里此测试 FAIL，
        // xc-pc-linux 上 PASS，差别只在行尾）。按 LF 规范化后再算，与 git blob 一致。
        let text = text.replace("\r\n", "\n");
        let lines: Vec<&str> = text.split('\n').collect();

        let hash_of =
            |start_pred: &dyn Fn(&str) -> bool, start: usize| -> Option<(String, usize)> {
                let i = start_pred;
                let start_idx = (start..lines.len()).find(|k| i(lines[*k]))?;
                let end_idx = (start_idx..lines.len()).find(|k| lines[*k].contains("契约 hash"))?;
                let body = lines[start_idx..end_idx].join("\n") + "\n";
                Some((sha256_hex(body.as_bytes()), end_idx))
            };
        // sha256（无外部依赖：harness 是 portable-core 工具，不引入依赖树）。
        fn sha256_hex(data: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        let (h1258, _) = hash_of(&|l: &str| l.starts_with("### §12.58"), 0)
            .expect("§12.58 must exist with a contract hash");
        let stored_1258 = lines
            .iter()
            .find(|l| l.contains(&h1258))
            .map(|l| l.contains("契约 hash"))
            .unwrap_or(false);
        assert!(
            stored_1258,
            "§12.58 hash must be reproducible with the documented method (got {h1258})"
        );

        let (h16, idx16) = hash_of(&|l: &str| l.starts_with("## 16."), 0)
            .expect("§16 must exist with a contract hash");
        assert!(
            lines[idx16].contains(&h16),
            "PRODUCT §16 contract hash is not reproducible: documented {} but computed {h16}",
            lines[idx16]
        );
    }

    #[test]
    fn product_freeze_hash_is_line_ending_independent() {
        // 冻结边界防篡改检查必须与 git blob（LF）对齐，而不是与某个宿主的 checkout
        // 字节（Windows 上 `* text=auto` 会给出 CRLF）对齐。这里锁定"同一内容、
        // 两种行尾 → 同一个 hash"，防止有人把规范化改回去而本宿主仍绿。
        fn sha256_hex(data: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
        let body = "### §12.58 标题\n\n正文一行。\n\n契约 hash: `x`\n";
        let crlf = body.replace('\n', "\r\n");
        assert_ne!(body, crlf, "fixture must actually differ in line endings");
        // 与实现里的做法一致：先规范化行尾再算。
        assert_eq!(
            sha256_hex(crlf.replace("\r\n", "\n").as_bytes()),
            sha256_hex(body.as_bytes()),
            "CRLF checkout must hash to the same value as the LF blob"
        );
        // 反面：不规范化就一定不一致（说明这条测试有意义）。
        assert_ne!(sha256_hex(crlf.as_bytes()), sha256_hex(body.as_bytes()));
    }

    #[test]
    fn affected_analysis_surfaces_git_failure_instead_of_empty_change_set() {
        // 独立 Review round 3 待办 1：`git diff --name-only HEAD` 与 porcelain 双双
        // `unwrap_or_default()` ⇒ git 失败时变更集为空 ⇒ affected-tests 门输出
        // "no affected crates changed" 并 **PASS**（fail-open）。现在必须上抛。
        let root = std::env::temp_dir().join(format!("harness-not-a-repo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let repo = crate::env::Repo { root: root.clone() };
        assert!(
            repo.git(&["rev-parse", "--show-toplevel"]).is_err(),
            "本测试需要一个不在任何 git 仓库内的临时目录，否则失败注入不成立"
        );
        let meta = serde_json::json!({ "packages": [] });
        let err = changed_member_names(&repo, &meta, &[])
            .expect_err("git 失败必须上抛，不能伪装成『没有变更』");
        assert!(
            err.contains("git diff"),
            "错误里要写明是哪一步取不到：{err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn affected_gate_is_unknown_when_git_fails() {
        // 门侧收口：git 取不到变更集时门记 UNKNOWN 并给出原因，而不是 PASS。
        let root =
            std::env::temp_dir().join(format!("harness-affected-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let repo = crate::env::Repo { root: root.clone() };
        let config = crate::config::Config::load(&crate::env::Repo::discover().expect("repo"))
            .expect("config");
        let gate = affected_tests_gate(&repo, &config, GateBudget::unlimited());
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(gate.name, "affected-tests");
        assert_eq!(
            gate.verdict, "UNKNOWN",
            "git 失败绝不能是 PASS：detail={}",
            gate.detail
        );
        assert!(
            gate.detail.contains("git"),
            "UNKNOWN 必须写明原因：{}",
            gate.detail
        );
    }

    // --- full gates：UNKNOWN 必须带具体原因；确定性判定必须可单测 ---

    #[test]
    fn unimplemented_gate_records_unknown_with_reason() {
        // 契约 §4.4：未实现 gate 记 UNKNOWN 且带原因，绝不静默 PASS。
        let g = unimplemented("some-future-gate");
        assert_eq!(g.name, "some-future-gate");
        assert_eq!(g.verdict, "UNKNOWN");
        assert!(g.detail.contains("not implemented"), "{}", g.detail);
    }

    #[test]
    fn performance_budgets_gate_requires_complete_thresholds() {
        let tmp = std::env::temp_dir().join(format!("harness-perf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = |quality: Value| Config {
            policies_dir: tmp.join("policies"),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.join("evidence"),
            crates_dir: tmp.join("crates"),
            engineering_dir: tmp.join("engineering"),
            quality,
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        // 完整 [performance]（baseline + blocking，对齐 policies/quality.toml）→ PASS。
        let g = performance_budgets_gate(
            &cfg(serde_json::json!({
                "performance": {
                    "baseline": {"policy_evaluate_ns": 1000},
                    "blocking": {"policy_evaluate_ns": 50000}
                }
            })),
            GateBudget::unlimited(),
        );
        assert_eq!(g.verdict, "PASS", "{}", g.detail);
        assert!(g.detail.contains("baseline"), "{}", g.detail);
        // 无 [performance] → UNKNOWN（无预算可查，不静默 PASS）。
        let g = performance_budgets_gate(&cfg(serde_json::json!({})), GateBudget::unlimited());
        assert_eq!(g.verdict, "UNKNOWN");
        assert!(
            g.detail.contains("no [performance] section"),
            "{}",
            g.detail
        );
        // 不完整（缺 blocking）→ UNKNOWN。
        let g = performance_budgets_gate(
            &cfg(serde_json::json!({"performance": {"baseline": {}}})),
            GateBudget::unlimited(),
        );
        assert_eq!(g.verdict, "UNKNOWN");
        assert!(g.detail.contains("incomplete"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn platform_checks_gate_detects_platform_specific_dependencies() {
        // portable-core crate 不得依赖平台专属 crate（平台 VPI 隔离）；
        // manifest 缺失 → FAIL（fail-closed，不静默跳过）。
        let tmp = std::env::temp_dir().join(format!("harness-plat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let crates = tmp.join("crates");
        std::fs::create_dir_all(crates.join("clean/src")).unwrap();
        std::fs::write(
            crates.join("clean/Cargo.toml"),
            "[package]\nname = \"clean\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(crates.join("win/src")).unwrap();
        std::fs::write(
            crates.join("win/Cargo.toml"),
            "[package]\nname = \"win\"\nversion = \"0.1.0\"\n\n[dependencies]\nwinapi = \"0.3\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(crates.join("tgt/src")).unwrap();
        std::fs::write(
            crates.join("tgt/Cargo.toml"),
            "[package]\nname = \"tgt\"\nversion = \"0.1.0\"\n\n[target.'cfg(windows)'.dependencies]\nfoo = \"1\"\n",
        )
        .unwrap();
        let cfg = |names: Vec<String>| Config {
            policies_dir: tmp.join("policies"),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.join("evidence"),
            crates_dir: crates.clone(),
            engineering_dir: tmp.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: names,
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        // 干净 crate → PASS。
        let g = platform_checks_gate(&cfg(vec!["clean".to_string()]), GateBudget::unlimited());
        assert_eq!(g.verdict, "PASS", "{}", g.detail);
        // 平台专属依赖 → FAIL 且点名依赖。
        let g = platform_checks_gate(
            &cfg(vec!["clean".to_string(), "win".to_string()]),
            GateBudget::unlimited(),
        );
        assert_eq!(g.verdict, "FAIL");
        assert!(g.detail.contains("winapi"), "{}", g.detail);
        // [target.'cfg(...)'.dependencies] → FAIL。
        let g = platform_checks_gate(&cfg(vec!["tgt".to_string()]), GateBudget::unlimited());
        assert_eq!(g.verdict, "FAIL");
        assert!(g.detail.contains("cfg("), "{}", g.detail);
        // manifest 缺失 → FAIL。
        let g = platform_checks_gate(&cfg(vec!["ghost".to_string()]), GateBudget::unlimited());
        assert_eq!(g.verdict, "FAIL");
        assert!(g.detail.contains("ghost"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn architecture_gate_fails_closed_on_missing_or_malformed_policy() {
        // policy 缺失/不可解析 → FAIL（fail-closed）。该路径在 cargo metadata
        // 之前返回，不依赖 workspace 元数据，确定性可测。
        let tmp = std::env::temp_dir().join(format!("harness-arch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = Config {
            policies_dir: tmp.clone(),
            scenarios_dir: tmp.join("scenarios"),
            evidence_dir: tmp.join("evidence"),
            crates_dir: tmp.join("crates"),
            engineering_dir: tmp.join("engineering"),
            quality: serde_json::json!({}),
            portable_core: vec![],
            bind_working_tree_digest: true,
            verify_timeouts: crate::config::VerifyTimeouts::defaults(),
        };
        let g = architecture_gate(&cfg, GateBudget::unlimited());
        assert_eq!(g.verdict, "FAIL", "{}", g.detail);
        assert!(g.detail.contains("read failed"), "{}", g.detail);
        std::fs::write(tmp.join("architecture.toml"), "not = = toml").unwrap();
        let g = architecture_gate(&cfg, GateBudget::unlimited());
        assert_eq!(g.verdict, "FAIL", "{}", g.detail);
        assert!(g.detail.contains("parse failed"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn concurrency_gate_unknown_when_no_tests_declared() {
        // tests/concurrency/ 无声明 → UNKNOWN 且带具体原因（不静默 PASS）。
        let tmp = std::env::temp_dir().join(format!("harness-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let repo = Repo { root: tmp.clone() };
        let g = concurrency_gate(&repo, GateBudget::unlimited());
        assert_eq!(g.verdict, "UNKNOWN", "{}", g.detail);
        assert!(g.detail.contains("tests/concurrency"), "{}", g.detail);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fuzz_gate_unknown_with_specific_reason() {
        // cargo-fuzz 未安装 → UNKNOWN（含安装提示）；已安装但临时目录无
        // fuzz/Cargo.toml → UNKNOWN（无 fuzz 目标）。两者都绝不静默 PASS。
        let tmp = std::env::temp_dir().join(format!("harness-fuzz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let repo = Repo { root: tmp.clone() };
        let g = fuzz_gate(&repo, GateBudget::unlimited());
        assert_eq!(g.verdict, "UNKNOWN", "{}", g.detail);
        if cargo_tool_available(&repo, "fuzz", GateBudget::unlimited()) {
            assert!(g.detail.contains("no fuzz targets"), "{}", g.detail);
        } else {
            assert!(
                g.detail.contains("cargo-fuzz not installed"),
                "{}",
                g.detail
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn coverage_gate_unknown_with_specific_reason() {
        // cargo-llvm-cov 未安装 → UNKNOWN（含安装提示）；已安装但临时目录不是
        // cargo workspace → UNKNOWN（coverage run failed）。不静默 PASS。
        let tmp = std::env::temp_dir().join(format!("harness-cov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let repo = Repo { root: tmp.clone() };
        let g = coverage_gate(&repo, GateBudget::unlimited());
        assert_eq!(g.verdict, "UNKNOWN", "{}", g.detail);
        if cargo_tool_available(&repo, "llvm-cov", GateBudget::unlimited()) {
            assert!(g.detail.contains("coverage run failed"), "{}", g.detail);
        } else {
            assert!(
                g.detail.contains("cargo-llvm-cov not installed"),
                "{}",
                g.detail
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn portable_core_gate_unknown_when_wasm_target_missing() {
        // wasm32-wasip1 未安装 → UNKNOWN（含安装提示）。已安装时跳过：
        // 真机编译路径缓慢，由 verify --full 覆盖。注意用全量输出判断
        // （run_at 的 12 行 tail 会在多 target 机器上漏掉 wasm32-wasip1）。
        let repo = Repo::discover().expect("repo must be discoverable");
        let installed = Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip1"))
            .unwrap_or(false);
        if installed {
            return;
        }
        let config = Config::load(&repo).expect("config must load");
        let g = portable_core_gate(&repo, &config, GateBudget::unlimited());
        assert_eq!(g.verdict, "UNKNOWN", "{}", g.detail);
        assert!(g.detail.contains("wasm32-wasip1"), "{}", g.detail);
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_times_out() {
        let root = std::env::temp_dir();
        let start = std::time::Instant::now();
        let outcome = run_bounded(
            &root,
            "sleep",
            &["5"],
            GateBudget::from_limit(Some(std::time::Duration::from_millis(50))),
        );
        assert!(
            matches!(outcome, CommandOutcome::TimedOut { .. }),
            "expected TimedOut"
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_captures_output() {
        let root = std::env::temp_dir();
        let outcome = run_bounded(
            &root,
            "sh",
            &["-c", "printf hello-out"],
            GateBudget::unlimited(),
        );
        match outcome {
            CommandOutcome::Exited { success, text } => {
                assert!(success);
                assert!(text.contains("hello-out"), "{text}");
            }
            _ => panic!("expected Exited"),
        }
    }
}
