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
}

impl Gate {
    pub fn ok(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "PASS".to_string(),
            detail: detail.to_string(),
        }
    }
    pub fn fail(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "FAIL".to_string(),
            detail: detail.to_string(),
        }
    }
    pub fn unknown(name: &str, detail: &str) -> Gate {
        Gate {
            name: name.to_string(),
            verdict: "UNKNOWN".to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Run a command in the repo root; returns (success, trimmed output tail).
fn run_at(root: &PathBuf, program: &str, args: &[&str]) -> (bool, String) {
    let (ok, text) = run_at_full(root, program, args);
    let tail: Vec<&str> = text.lines().rev().take(12).collect();
    let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
    (ok, tail)
}

/// Run a command in the repo root; returns (success, full combined output).
fn run_at_full(root: &PathBuf, program: &str, args: &[&str]) -> (bool, String) {
    let out = match Command::new(program).args(args).current_dir(root).output() {
        Ok(o) => o,
        Err(e) => return (false, format!("failed to run {program}: {e}")),
    };
    let ok = out.status.success();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (ok, text)
}

fn cargo(repo: &Repo, args: &[&str]) -> Gate {
    let (ok, out) = run_at(&repo.root, "cargo", args);
    if ok {
        Gate::ok("", "ok")
    } else {
        Gate::fail(
            "",
            if out.is_empty() {
                "command failed"
            } else {
                &out
            },
        )
    }
}

pub fn whitespace_gate(repo: &Repo) -> Gate {
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

pub fn format_gate(repo: &Repo) -> Gate {
    let g = cargo(repo, &["fmt", "--all", "--", "--check"]);
    Gate {
        name: "format".to_string(),
        ..g
    }
}

pub fn check_gate(repo: &Repo) -> Gate {
    let g = cargo(repo, &["check", "--workspace", "--all-targets"]);
    Gate {
        name: "check".to_string(),
        ..g
    }
}

pub fn clippy_gate(repo: &Repo) -> Gate {
    let g = cargo(
        repo,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    );
    Gate {
        name: "clippy".to_string(),
        ..g
    }
}

/// Unit tests of the harness itself (selected properties gate).
pub fn selected_properties_gate(repo: &Repo) -> Gate {
    let g = cargo(repo, &["test", "-p", "nexus-harness"]);
    Gate {
        name: "selected-properties".to_string(),
        ..g
    }
}

pub fn workspace_tests_gate(repo: &Repo) -> Gate {
    let g = cargo(repo, &["test", "--workspace"]);
    Gate {
        name: "workspace-tests".to_string(),
        ..g
    }
}

/// Affected analysis: changed files -> owning crates -> direct reverse deps.
/// Tests every affected crate; no changes => PASS.
pub fn affected_tests_gate(repo: &Repo, _config: &Config) -> Gate {
    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => return Gate::unknown("affected-tests", &format!("cargo metadata failed: {e}")),
    };
    let members = member_names(&meta);
    let affected = changed_member_names(repo, &meta, &members);
    if affected.is_empty() {
        return Gate::ok("affected-tests", "no affected crates changed");
    }
    let mut failures: Vec<String> = Vec::new();
    for name in &affected {
        let g = cargo(repo, &["test", "-p", name]);
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

fn changed_member_names(repo: &Repo, meta: &Value, members: &[String]) -> Vec<String> {
    let manifests = member_manifests(meta);
    let mut changed: Vec<String> = Vec::new();

    // committed changes vs HEAD
    let tracked = repo
        .git(&["diff", "--name-only", "HEAD"])
        .unwrap_or_default();
    let mut files: Vec<String> = tracked.lines().map(str::to_string).collect();
    // untracked additions
    for line in repo.porcelain().lines() {
        if let Some(rest) = line.strip_prefix("?? ") {
            files.push(rest.to_string());
        }
    }

    for f in &files {
        let abs = repo.root.join(f);
        for (name, dir) in &manifests {
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
    with_rev
}

/// Light architecture gate: every `crates/*` workspace member must be declared
/// in policies/architecture.toml [[crate]] (apps/engineering are hosts/tooling).
pub fn architecture_gate(config: &Config) -> Gate {
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
pub fn dependency_gate(repo: &Repo, config: &Config) -> Gate {
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
    if !cargo_tool_available(repo, "deny") {
        return Gate::unknown(
            "dependency-governance",
            "static checks passed; cargo-deny not installed (install with: cargo install cargo-deny --locked)",
        );
    }
    let deny_cfg = config.policies_dir.join("deny.toml");
    let (ok, out) = run_at_full(
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
    );
    if ok {
        Gate::ok(
            "dependency-governance",
            "cargo-deny: advisories/licenses/bans/sources PASS",
        )
    } else {
        let tail: Vec<&str> = out.lines().rev().take(20).collect();
        let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
        Gate::fail(
            "dependency-governance",
            &format!("cargo-deny check FAILED:\n{tail}"),
        )
    }
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
fn cargo_tool_available(repo: &Repo, subcmd: &str) -> bool {
    let (ok, _) = run_at(&repo.root, "cargo", &[subcmd, "--version"]);
    ok
}

/// Integration tests: every workspace member's tests/ dir. Runs each via
/// `cargo test -p <member> --test <name>`; none declared => UNKNOWN.
pub fn integration_gate(repo: &Repo) -> Gate {
    let meta = match cargo_metadata() {
        Ok(m) => m,
        Err(e) => return Gate::unknown("integration", &format!("cargo metadata failed: {e}")),
    };
    let mut targets: Vec<(String, String)> = Vec::new(); // (member, test name)
    for (name, dir) in member_manifests(&meta) {
        for f in rs_files_under(&dir.join("tests")) {
            if let Some(stem) = f.file_stem().map(|s| s.to_string_lossy().to_string()) {
                targets.push((name.clone(), stem));
            }
        }
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Gate::unknown(
            "integration",
            "no integration test targets declared (no member has tests/*.rs)",
        );
    }
    let mut failures: Vec<String> = Vec::new();
    for (member, test) in &targets {
        let g = cargo(repo, &["test", "-p", member, "--test", test]);
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
pub fn coverage_gate(repo: &Repo) -> Gate {
    if !cargo_tool_available(repo, "llvm-cov") {
        return Gate::unknown(
            "coverage-summary",
            "cargo-llvm-cov not installed (install with: cargo install cargo-llvm-cov)",
        );
    }
    let (ok, out) = run_at_full(
        &repo.root,
        "cargo",
        &["llvm-cov", "--workspace", "--summary-only"],
    );
    if !ok {
        return Gate::unknown("coverage-summary", &format!("coverage run failed: {}", out));
    }
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
pub fn fuzz_gate(repo: &Repo) -> Gate {
    if !cargo_tool_available(repo, "fuzz") {
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
    let (ok, out) = run_at(&repo.root, "cargo", &["+nightly", "fuzz", "check"]);
    if ok {
        Gate::ok("selected-fuzz", "ok")
    } else {
        Gate::fail(
            "selected-fuzz",
            if out.is_empty() {
                "command failed"
            } else {
                &out
            },
        )
    }
}

/// Concurrency tests under tests/concurrency/; none declared => UNKNOWN.
pub fn concurrency_gate(repo: &Repo) -> Gate {
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
        let g = cargo(repo, &["test", "--test", &stem]);
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
pub fn bench_gate(repo: &Repo, _config: &Config) -> Gate {
    let (ok, text) = run_at_full(
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
    );
    if !ok {
        return Gate::unknown(
            "bench",
            &format!("perf_bench run failed (exit != 0): {}", text.trim()),
        );
    }
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
pub fn performance_budgets_gate(config: &Config) -> Gate {
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
pub fn platform_checks_gate(config: &Config) -> Gate {
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
pub fn feature_matrix_gate(repo: &Repo) -> Gate {
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
            let g = cargo(repo, &["check", "-p", name, flag]);
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
pub fn portable_core_gate(repo: &Repo, config: &Config) -> Gate {
    let (ok, out) = run_at(&repo.root, "rustup", &["target", "list", "--installed"]);
    if !ok || !out.contains("wasm32-wasip1") {
        return Gate::unknown(
            "portable-core",
            "wasm32-wasip1 target not installed (install with: rustup target add wasm32-wasip1)",
        );
    }
    let mut failures: Vec<String> = Vec::new();
    for name in &config.portable_core {
        let g = cargo(repo, &["check", "-p", name, "--target", "wasm32-wasip1"]);
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
/// N2 资源类型中立门禁（P0-6，完成标志 #6）：四 crate 零资源类型专属分支。
///
/// 扫描 `policies/architecture.toml [resource_kind_neutrality]` 声明的 crate 的
/// `src/**/*.rs`；flag 同时含"变体引用"（`ResourceKind::V` / `Self::V`，词边界）
/// 与"分支 token"（`=>` / `matches!` / `if`+`==`/`!=`）的代码行；命中 allow
/// 列表的除外。fail-closed：policy 缺失/字段缺失 → FAIL。
pub fn resource_kind_neutrality_gate(config: &Config) -> Gate {
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
    let allows: Vec<(String, String)> = section
        .get("allow")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let file = e.get("file")?.as_str()?.to_string();
                    let contains = e.get("contains")?.as_str()?.to_string();
                    Some((file, contains))
                })
                .collect()
        })
        .unwrap_or_default();
    let repo_root = config.policies_dir.parent().unwrap_or(&config.policies_dir);

    let mut violations: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;
    for krate in &crates {
        for f in rs_files_under(&config.crates_dir.join(krate).join("src")) {
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
            for (idx, line) in text.lines().enumerate() {
                let code = strip_line_code(line, &mut block_depth);
                if !is_specialized_branch(&code, &variants) {
                    continue;
                }
                let allowed = allows
                    .iter()
                    .any(|(file, contains)| *file == rel && code.contains(contains));
                if !allowed {
                    violations.push(format!("{rel}:{}: {}", idx + 1, code.trim()));
                }
            }
        }
    }
    if violations.is_empty() {
        Gate::ok(
            GATE,
            &format!(
                "{} crate(s), {scanned_files} file(s): no resource-type-specialized branches",
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
        let g = dependency_gate(&repo, &config);
        assert_ne!(g.verdict, "FAIL", "dependency gate failed: {}", g.detail);
        if cargo_tool_available(&repo, "deny") {
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
        // 当前四 crate 无资源类型专属分支（仅 as_str 规范序列化，已 allow）。
        let repo = crate::env::Repo::discover().expect("repo must be discoverable");
        let config = crate::config::Config::load(&repo).expect("config must load");
        let g = resource_kind_neutrality_gate(&config);
        assert_eq!(g.verdict, "PASS", "gate failed: {}", g.detail);
        assert!(g.detail.contains("4 crate(s)"), "{}", g.detail);
    }
}
