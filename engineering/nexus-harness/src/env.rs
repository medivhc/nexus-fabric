//! Repository/environment introspection: git state, toolchain, digests.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Repo {
    pub root: PathBuf,
}

impl Repo {
    /// Discover the repository root via `git rev-parse --show-toplevel`.
    pub fn discover() -> Result<Repo, String> {
        let out = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|e| format!("failed to run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "not a git repository (or git unavailable): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let root = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
        Ok(Repo { root })
    }

    /// Run git in the repo root; returns trimmed stdout.
    pub fn git(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Hash a string through `git hash-object --stdin` (sha1, no crypto dep).
    pub fn hash_stdin(&self, data: &str) -> Result<String, String> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["hash-object", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn git hash-object: {e}"))?;
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .ok_or("no stdin")?
            .write_all(data.as_bytes())
            .map_err(|e| format!("failed to write stdin: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait git hash-object: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git hash-object failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub fn revision(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
            .unwrap_or_else(|_| "no-commit".to_string())
    }

    pub fn porcelain(&self) -> String {
        self.git(&["status", "--porcelain"]).unwrap_or_default()
    }

    pub fn is_dirty(&self) -> bool {
        !self.porcelain().is_empty()
    }

    /// Digest of the working tree: index tree when clean, otherwise a hash of
    /// the porcelain output (stable for a given dirty state).
    pub fn working_tree_digest(&self) -> String {
        if self.is_dirty() {
            self.hash_stdin(&self.porcelain())
                .unwrap_or_else(|_| "dirty-unknown".to_string())
        } else {
            self.git(&["write-tree"])
                .unwrap_or_else(|_| "tree-unknown".to_string())
        }
    }

    /// Digest over configuration inputs that affect verification conclusions
    /// (harness.toml + policies/*.toml + workspace manifests).
    pub fn configuration_digest(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for rel in [
            "harness.toml",
            "Cargo.toml",
            "engineering/nexus-harness/Cargo.toml",
        ] {
            if let Ok(c) = std::fs::read_to_string(self.root.join(rel)) {
                parts.push(format!("{rel}\n{c}"));
            }
        }
        if let Ok(entries) = std::fs::read_dir(self.root.join("policies")) {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            names.sort();
            for n in names {
                if let Ok(c) = std::fs::read_to_string(self.root.join("policies").join(&n)) {
                    parts.push(format!("policies/{n}\n{c}"));
                }
            }
        }
        self.hash_stdin(&parts.join("\n===\n"))
            .unwrap_or_else(|_| "config-unknown".to_string())
    }

    /// Digest over the scenario contract set (scenarios/**/*.toml).
    pub fn contract_hash(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.root.join("scenarios")) {
            let mut dirs: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            dirs.sort();
            for d in dirs {
                if let Ok(files) = std::fs::read_dir(self.root.join("scenarios").join(&d)) {
                    let mut names: Vec<String> = files
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect();
                    names.sort();
                    for n in names {
                        if let Ok(c) =
                            std::fs::read_to_string(self.root.join("scenarios").join(&d).join(&n))
                        {
                            parts.push(format!("scenarios/{d}/{n}\n{c}"));
                        }
                    }
                }
            }
        }
        self.hash_stdin(&parts.join("\n===\n"))
            .unwrap_or_else(|_| "contract-unknown".to_string())
    }

    pub fn resolve(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

/// Toolchain/target info from `rustc -vV`.
pub fn toolchain() -> (String, String) {
    let out = Command::new("rustc").arg("-vV").output();
    let Ok(out) = out else {
        return ("unknown".to_string(), "unknown".to_string());
    };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let release = text
        .lines()
        .find_map(|l| l.strip_prefix("release:"))
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let host = text
        .lines()
        .find_map(|l| l.strip_prefix("host:"))
        .unwrap_or("unknown")
        .trim()
        .to_string();
    (release, host)
}

/// Platform capability digest (OS/arch/family), bound into evidence.
pub fn platform_digest(repo: &Repo) -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let family = std::env::consts::FAMILY;
    repo.hash_stdin(&format!("{os}\n{arch}\n{family}"))
        .unwrap_or_else(|_| "platform-unknown".to_string())
}

/// Parse `cargo metadata` JSON; returns packages (name, manifest_path) and
/// direct dependency edges. Used by affected analysis.
pub fn cargo_metadata() -> Result<Value, String> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("bad cargo metadata JSON: {e}"))
}

pub fn path_is_within(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir)
}
