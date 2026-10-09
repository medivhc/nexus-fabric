//! Repository/environment introspection: git state, toolchain, digests.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// git 的 `.git/index.lock` 是极短临界区。同一测试二进制并发跑（默认多线程）时，
/// `write-tree` / `status` 会撞锁失败；调用方把失败降级成哨兵值
/// （`tree-unknown` / `dirty-unknown` / 空串），于是出现"digest 不确定"的**假失败**
/// （实测 `env::tests::digests_deterministic_and_sha1_length` 在 Linux 上偶发红）。
/// 这里只对真正的锁竞争重试，其它错误原样上报，不吞任何失败。
const GIT_LOCK_RETRIES: u32 = 4;
const GIT_LOCK_BACKOFF: Duration = Duration::from_millis(25);

/// 判定 stderr 是否为 git 索引/引用锁竞争（大小写不敏感）。
fn is_lock_contention(stderr: &str) -> bool {
    let hay = stderr.to_ascii_lowercase();
    hay.contains("index.lock")
        || hay.contains("cannot lock ref")
        || (hay.contains("unable to create") && hay.contains("lock"))
}

pub struct Repo {
    pub root: PathBuf,
}

impl Repo {
    /// Discover the repository root via `git rev-parse --show-toplevel`.
    ///
    /// `GIT_DIR` / `GIT_WORK_TREE` 会被显式剥离：git 在执行 hook
    /// （如 pre-push）时会设置 `GIT_DIR`，此时 `--show-toplevel`
    /// 返回的是子进程 CWD 而非真正的 worktree 根，导致
    /// `Repo::discover` 拿到错误的 root（2026-10-06 真实踩坑：
    /// hook 内 verify --fast 的 selected-properties 门因此 FAIL）。
    /// discover 的语义是"从 CWD 发现仓库"，必须不受调用方 git 环境污染。
    pub fn discover() -> Result<Repo, String> {
        let mut cmd = Command::new("git");
        Self::discover_in(&mut cmd)
    }

    /// discover 的可注入版本（测试用）：调用方可先在 cmd 上预置环境变量，
    /// 再走与 discover() 完全相同的剥离逻辑。
    fn discover_in(cmd: &mut Command) -> Result<Repo, String> {
        let out = cmd
            .args(["rev-parse", "--show-toplevel"])
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
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
    ///
    /// 仅对锁竞争重试（见 `GIT_LOCK_RETRIES`），退避 25/50/75ms；其余失败立即返回 Err。
    pub fn git(&self, args: &[&str]) -> Result<String, String> {
        let mut attempt = 1u32;
        loop {
            let out = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .map_err(|e| format!("failed to run git: {e}"))?;
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let message = format!("git {} failed: {}", args.join(" "), stderr);
            if attempt < GIT_LOCK_RETRIES && is_lock_contention(&stderr) {
                std::thread::sleep(GIT_LOCK_BACKOFF * attempt);
                attempt += 1;
                continue;
            }
            return Err(message);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_deterministic_and_sha1_length() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        // 降级哨兵值（`*-unknown`）代表"没取到"，不能算成一次确定的取值：
        // 之前它就是靠 assert_eq!(f(), f()) 两次都拿到同一个哨兵而蒙过去的。
        for (name, first, second) in [
            (
                "configuration_digest",
                repo.configuration_digest(),
                repo.configuration_digest(),
            ),
            ("contract_hash", repo.contract_hash(), repo.contract_hash()),
            (
                "working_tree_digest",
                repo.working_tree_digest(),
                repo.working_tree_digest(),
            ),
        ] {
            assert_eq!(first, second, "{name} 两次取值不一致");
            assert!(
                !first.ends_with("-unknown"),
                "{name} 取到降级哨兵值 {first}：git 调用失败，不得当作确定取值"
            );
        }
        assert_eq!(repo.hash_stdin("abc").unwrap().len(), 40);
    }

    /// 锁竞争判定必须只认 git 的锁类错误：把普通失败也拿去重试会掩盖真故障。
    #[test]
    fn lock_contention_detection_covers_git_lock_messages_only() {
        assert!(is_lock_contention(
            "fatal:Unable to create '/repo/.git/index.lock': File exists."
        ));
        assert!(is_lock_contention(
            "fatal: Unable to create '/repo/.git/index.lock': Permission denied"
        ));
        assert!(is_lock_contention("fatal: cannot lock ref 'HEAD'"));
        assert!(!is_lock_contention("fatal: not a git repository"));
        assert!(!is_lock_contention(
            "error: pathspec 'nope' did not match any file(s)"
        ));
    }

    #[test]
    fn hash_depends_on_input() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        assert_ne!(repo.hash_stdin("a").unwrap(), repo.hash_stdin("b").unwrap());
    }

    /// 回归：`Repo::discover` 不受调用方 `GIT_DIR` 污染。
    /// git 执行 hook（如 pre-push）时会设置 `GIT_DIR`，此时若不剥离，
    /// `git rev-parse --show-toplevel` 返回子进程 CWD 而非 worktree 根
    /// （2026-10-06 真实踩坑：hook 内 verify --fast 的 selected-properties
    /// 门因此 FAIL，push 被门禁拦下）。
    #[test]
    fn discover_ignores_caller_git_dir() {
        // 干净的 worktree 根做断言基准。
        let expected = Repo::discover()
            .expect("must run inside the nexus repository")
            .root
            .to_string_lossy()
            .to_string();

        // 模拟 hook 污染：在 Command 上预置 GIT_DIR（指向 worktree gitfile），
        // 再走与 discover() 完全相同的剥离逻辑；结果必须仍是真正的根。
        let gitfile = Path::new(&expected).join(".git");
        let mut cmd = Command::new("git");
        cmd.env("GIT_DIR", &gitfile);
        let repo = Repo::discover_in(&mut cmd).expect("discover must succeed under GIT_DIR");
        assert_eq!(repo.root.to_string_lossy(), expected.as_str());
    }
}
