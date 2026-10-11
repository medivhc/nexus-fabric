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

    /// `git status --porcelain` 原始输出，**保留失败**：调用方不得把"问不到"当成"干净"。
    ///
    /// 这里刻意**没有** `porcelain() -> String` 这种吞掉 `Err` 的便捷包装：round 2/3
    /// 两次独立 Review 都在同一个地方踩到 fail-open（Evidence 的 `dirty_state`、
    /// affected 分析的变更集），根因就是有一个把失败读成"空输出 = 干净/无变更"的
    /// 默认值可用。失败必须由调用方显式决定记 UNKNOWN 还是 FAIL。
    pub fn porcelain_result(&self) -> Result<String, String> {
        self.git(&["status", "--porcelain"])
    }

    /// `None` = git 查询失败。独立 Review round 2 记的 fail-open 缺口就在这里：
    /// 旧实现 `unwrap_or_default()` 会把"问不到"写成 `dirty_state: false`，
    /// 于是 Evidence 里出现一条正面事实"工作树干净"。
    pub fn dirty_state(&self) -> Option<bool> {
        self.porcelain_result().map(|p| !p.is_empty()).ok()
    }

    /// Digest of the working tree: index tree when clean, otherwise a hash of
    /// the porcelain output (stable for a given dirty state).
    ///
    /// 只问一次 `git status`（旧实现问两次，既多一倍开销又多一倍 index.lock 竞争面）。
    /// 问不到状态时返回哨兵值 `dirty-unknown`，由调用方显式处理
    /// （`code_intel::digest_is_unusable` 就是那个"显式处理"）。
    pub fn working_tree_digest(&self) -> String {
        match self.porcelain_result() {
            Ok(porcelain) if porcelain.is_empty() => self
                .git(&["write-tree"])
                .unwrap_or_else(|_| "tree-unknown".to_string()),
            Ok(porcelain) => self
                .hash_stdin(&porcelain)
                .unwrap_or_else(|_| "dirty-unknown".to_string()),
            Err(_) => "dirty-unknown".to_string(),
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

/// `std::fs::canonicalize` 的 Option 形态：失败（不存在、无权限、跨卷…）返回 None。
pub fn canonicalized(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// **文件系统视角**的包含关系：两侧都先 canonicalize，再按路径组件比较。
///
/// 为什么不能用 `path_is_within`：`fixtures/../../../../run-scenarios.sh` 在词法上
/// 以仓库根为前缀，实际指向仓库之外（独立 Review round 2 的 B-R2-1 就是这条通路把查询
/// 目标送出仓库、并让子进程 cwd 落在仓库外的）。canonicalize 同时解决三类假阳/假阴：
/// `.`/`..` 组件、符号链接与 Windows junction、盘符大小写。
///
/// fail-closed 语义：任一侧归一化失败即返回 false —— 调用方必须把 false 当作
/// "无法证明在范围内"并显式报错，不得当成通过。
pub fn path_is_within_resolved(path: &Path, dir: &Path) -> bool {
    match (canonicalized(path), canonicalized(dir)) {
        (Some(p), Some(d)) => p.starts_with(&d),
        _ => false,
    }
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

    /// B-R2-1 的根因测试：词法前缀判定会被 `..` 骗过，归一化判定不会。
    /// 两条断言合起来才说明问题——先证明缺陷形状仍然存在（词法判"在内"），
    /// 再证明修复后的判定把它挡下（canonical 判"越界"）。
    #[test]
    fn resolved_containment_blocks_dotdot_that_lexical_allows() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let root = repo.root.clone();
        let ws = root.join("engineering").join("nexus-harness");
        // engineering/nexus-harness/src/../../../crates/nexus-domain/Cargo.toml
        //   == <repo>/crates/nexus-domain/Cargo.toml —— 在仓库内、在 workspace 外。
        let escapee = ws
            .join("src")
            .join("..")
            .join("..")
            .join("..")
            .join("crates")
            .join("nexus-domain")
            .join("Cargo.toml");
        assert!(escapee.is_file(), "夹具路径失效：{}", escapee.display());
        assert!(
            path_is_within(&escapee, &ws),
            "词法判定仍命中前缀——这正是 round 2 缺陷的来源"
        );
        assert!(
            !path_is_within_resolved(&escapee, &ws),
            "归一化后必须判为越界"
        );
        // 同一棵树里的冗余 `.`/`..` 组合不该被误判为越界（避免修复过头）。
        let legit = ws
            .join("src")
            .join(".")
            .join("..")
            .join("src")
            .join("main.rs");
        assert!(legit.is_file(), "夹具路径失效：{}", legit.display());
        assert!(
            path_is_within_resolved(&legit, &ws),
            "canonical 后仍在 workspace 内"
        );
        // 归一化失败（不存在）必须是"无法证明"，不是"通过"。
        let ghost = ws.join("nope-does-not-exist");
        assert!(!path_is_within_resolved(&ghost, &ws));
    }

    /// 符号链接越界形态的**跨宿主固化**（round 3 待办 5）。
    ///
    /// 这一形态此前只有 xc-pc-linux 上的一次手工实测（`.agents/green-evidence-…txt` §G），
    /// Windows 侧因无特权建链接而无人复现。这里用 `#[cfg(unix)]` 把它变成回归测试：
    /// workspace 内放一个指向 workspace 外的链接文件，归一化判定必须拒绝，而词法判定
    /// 必须仍然"放过"——否则测试没有覆盖到缺陷本身。
    #[cfg(unix)]
    #[test]
    fn resolved_containment_blocks_symlink_escape_that_lexical_allows() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("nexus-symescape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("ws")).expect("temp ws");
        // 真实文件在 workspace 之外。
        std::fs::create_dir_all(&base).expect("temp base");
        let outside = base.join("outside.rs");
        std::fs::write(&outside, "pub fn outside() {}\n").expect("write outside");
        // workspace 内的链接指向它。
        let link = base.join("ws").join("link.rs");
        symlink(&outside, &link).expect("symlink");
        let ws = base.join("ws");
        assert!(
            path_is_within(&link, &ws),
            "词法判定放过链接——这正是必须被归一化堵住的形态"
        );
        assert!(
            !path_is_within_resolved(&link, &ws),
            "canonical 后链接目标是 workspace 外的真实文件，必须判为越界"
        );
        // 同目录内的普通文件仍须放行（避免修复过头）。
        let inside = ws.join("real.rs");
        std::fs::write(&inside, "pub fn inside() {}\n").expect("write inside");
        assert!(path_is_within_resolved(&inside, &ws));
        let _ = std::fs::remove_dir_all(&base);
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
