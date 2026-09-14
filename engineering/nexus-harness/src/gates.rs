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
    let tail: Vec<&str> = text.lines().rev().take(12).collect();
    let tail = tail.iter().rev().cloned().collect::<Vec<_>>().join("\n");
    (ok, tail)
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

/// Workspace member package names (from cargo metadata).
fn member_names(meta: &Value) -> Vec<String> {
    meta["workspace_members"]
        .as_array()
        .map(|ids| {
            let mut names = Vec::new();
            for id in ids {
                let id = id.as_str().unwrap_or("");
                // id format: path+file:///.../<dir>#<name>@<version>
                if let Some(hash) = id.split_once('#') {
                    if let Some(name) = hash.1.split_once('@') {
                        names.push(name.0.to_string());
                    }
                }
            }
            names
        })
        .unwrap_or_default()
}

/// Packages (name, manifest dir) for all members.
fn member_manifests(meta: &Value) -> Vec<(String, PathBuf)> {
    meta["packages"]
        .as_array()
        .map(|pkgs| {
            pkgs.iter()
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

pub fn unimplemented(name: &str) -> Gate {
    Gate::unknown(
        name,
        "gate not implemented in MVP harness (recorded UNKNOWN, not silently passed)",
    )
}
