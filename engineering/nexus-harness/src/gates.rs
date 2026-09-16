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
    match toml::from_str::<toml::Value>(&text) {
        Ok(_) => Gate::ok(
            "dependency-governance",
            "Cargo.lock present; dependencies.toml parses",
        ),
        Err(e) => Gate::fail("dependency-governance", &format!("parse failed: {e}")),
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
}
