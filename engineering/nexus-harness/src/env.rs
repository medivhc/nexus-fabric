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
        self.git_bytes(args)
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
    }

    /// Run git in the repo root; returns **raw** stdout bytes (no trim, no
    /// lossy UTF-8). Required by binary-safe consumers (`git diff --binary`,
    /// `-z` path lists): trimming would strip the leading ` ` of porcelain
    /// ` M path` lines and destroy binary hunk payloads, both of which carry
    /// meaning for content digests.
    ///
    /// 仅对锁竞争重试（见 `GIT_LOCK_RETRIES`），退避 25/50/75ms；其余失败立即返回 Err。
    /// 重试住在字节版里，`git()` 只是它的 trim 包装：两条调用路径共享同一
    /// 锁竞争语义，不会出现"`git()` 重试而 `diff --binary` 不重试"的分裂。
    pub fn git_bytes(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let mut attempt = 1u32;
        loop {
            let out = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .map_err(|e| format!("failed to run git: {e}"))?;
            if out.status.success() {
                return Ok(out.stdout);
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
        self.hash_stdin_bytes(data.as_bytes())
    }

    /// Byte-exact variant of [`hash_stdin`](Repo::hash_stdin) for inputs that
    /// are not valid UTF-8 (binary diffs).
    pub fn hash_stdin_bytes(&self, data: &[u8]) -> Result<String, String> {
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
            .write_all(data)
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

    /// Digest of the working tree: index tree (`git write-tree`) when clean;
    /// when dirty, a **content-bound** hash — see
    /// [`dirty_content_digest`](Repo::dirty_content_digest).
    ///
    /// 历史缺陷（2026-10-11 立案，EXP4/EXP5）：dirty 分支曾对
    /// `git status --porcelain` 文本做哈希。porcelain 只含状态码+路径，不含
    /// 字节：同路径下改内容 digest 不变，未跟踪目录整体换内容 digest 恒不变；
    /// 且 `git()` 的 `trim()` 还会剥掉首行行首空格，破坏 ` M path` 的 X 列语义。
    /// 现 dirty 分支不再依赖 porcelain 文本。
    ///
    /// 只问一次 `git status`（旧实现问两次，既多一倍开销又多一倍 index.lock
    /// 竞争面）。三种失败各自返回**不同**哨兵值，绝不折叠成正面结论：
    ///
    /// - porcelain 查询失败 → `dirty-unknown`（不知道脏净，不假装干净）
    /// - 脏但内容取不到 → `dirty-unknown`
    /// - 干净但 `write-tree` 失败 → `tree-unknown`
    ///
    /// `code_intel::digest_is_unusable` 就是那个"调用方显式处理"。
    pub fn working_tree_digest(&self) -> String {
        match self.porcelain_result() {
            Ok(porcelain) if porcelain.is_empty() => self
                .git(&["write-tree"])
                .unwrap_or_else(|_| "tree-unknown".to_string()),
            Ok(_) => self
                .dirty_content_digest()
                .unwrap_or_else(|_| "dirty-unknown".to_string()),
            Err(_) => "dirty-unknown".to_string(),
        }
    }

    /// Content-bound digest of a dirty working tree, built from two
    /// deterministic byte streams and hashed once through
    /// `git hash-object --stdin`:
    ///
    /// 1. **tracked 改动**：`git diff HEAD --binary` 的原始输出。`diff HEAD`
    ///    同时覆盖 staged 与 unstaged（相对 HEAD 的工作树最终态），并含
    ///    模式变更与删除，故不再单独哈希 index（避免重复计数）。
    ///    无 HEAD（空仓库/unborn branch）时退为 `git ls-files -s`（绑定
    ///    staged blob oid）叠加 `git diff --binary`（index→工作树的未暂存
    ///    改动），两者都以 0x00 分隔拼接。
    /// 2. **未跟踪文件**：`git ls-files --others --exclude-standard -z`
    ///    逐文件枚举（不折叠目录），每个路径用 `git hash-object -- <path>`
    ///    绑定工作树字节，产出 `path oid` 行并排序保证确定性。读被
    ///    .gitignore 尊重：忽略物按契约不属于工程状态。
    ///
    /// 两个分量各自 `?` 上抛：任何一侧查不到就整体失败，由
    /// [`working_tree_digest`](Repo::working_tree_digest) 落成 `dirty-unknown`
    /// 哨兵。不得用空字节凑出一个"看似正常"的 digest——那正是 #12 独立 Review
    /// 在别处收口的 fail-open 形态。单文件 `hash-object` 失败是例外（下述）。
    fn dirty_content_digest(&self) -> Result<String, String> {
        let tracked = match self.git_bytes(&["diff", "HEAD", "--binary"]) {
            Ok(b) => b,
            Err(_) => {
                // unborn branch（无 HEAD）：绑定 index 条目 + 未暂存 diff。
                // 备用查询任一失败同样上抛，不静默降级。
                let mut v = self.git_bytes(&["ls-files", "-s"])?;
                v.push(0u8);
                v.extend(self.git_bytes(&["diff", "--binary"])?);
                v
            }
        };
        let others = self.git_bytes(&["ls-files", "--others", "--exclude-standard", "-z"])?;
        let mut lines: Vec<String> = Vec::new();
        for path in others.split(|b| *b == 0u8).filter(|p| !p.is_empty()) {
            let rel = String::from_utf8_lossy(path).to_string();
            // 单文件哈希失败（竞态删除、权限）→ 记录稳定标记而非 panic；
            // 路径本身仍在 digest 里，不丢"存在性"绑定。
            let oid = self
                .git(&["hash-object", "--", &rel])
                .unwrap_or_else(|_| "unreadable".to_string());
            lines.push(format!("{rel} {oid}"));
        }
        lines.sort();
        let mut combined = tracked;
        combined.push(0u8);
        combined.extend_from_slice(lines.join("\n").as_bytes());
        self.hash_stdin_bytes(&combined)
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
pub(crate) mod tests {
    use super::*;

    /// 临时 git 仓库沙盒：`git init` + 仓库本地身份/行尾配置，
    /// 不依赖网络、不依赖宿主机的 global git config（user.email 等）。
    /// evidence.rs 的同 id 覆写保护测试也复用此构造器。
    pub(crate) fn init_temp_repo(tag: &str) -> Repo {
        let dir = std::env::temp_dir().join(format!(
            "nexus-harness-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        let repo = Repo { root: dir };
        for args in [
            vec!["init"],
            vec!["config", "user.email", "harness-test@example.invalid"],
            vec!["config", "user.name", "harness-test"],
            vec!["config", "core.autocrlf", "false"],
            // 宿主 global config 不得渗入沙盒：commit.gpgsign=true 会让测试
            // commit 失败，core.hooksPath 会把外部钩子挂进来。
            vec!["config", "commit.gpgsign", "false"],
            vec!["config", "core.hooksPath", ".git/hooks"],
        ] {
            repo.git(&args)
                .unwrap_or_else(|e| panic!("sandbox setup `git {args:?}` failed: {e}"));
        }
        repo
    }

    /// 在沙盒里写文件并提交一次，制造 clean 基线。
    pub(crate) fn commit_baseline(repo: &Repo, name: &str, content: &str) {
        std::fs::write(repo.resolve(name), content).expect("write baseline");
        repo.git(&["add", "-A"]).unwrap();
        repo.git(&["commit", "--no-verify", "-m", "baseline"])
            .unwrap();
    }

    #[test]
    fn dirty_digest_binds_file_content() {
        // 守住缺陷本体：porcelain 文本完全相同、仅字节不同 → digest 必须变。
        // 旧实现（hash porcelain）在此断言必红。
        let repo = init_temp_repo("content");
        commit_baseline(&repo, "lib.rs", "fn main() {}\n");
        std::fs::write(repo.resolve("lib.rs"), "fn main() {}\n// marker A\n").unwrap();
        let d1 = repo.working_tree_digest();
        let p1 = repo.porcelain_result().unwrap();
        assert!(!p1.is_empty(), "tree must be dirty here");
        std::fs::write(
            repo.resolve("lib.rs"),
            "fn main() {}\n// marker A plus a substantially longer second line\n",
        )
        .unwrap();
        let p2 = repo.porcelain_result().unwrap();
        assert_eq!(
            p1, p2,
            "porcelain identical by construction (same path, same XY)"
        );
        let d2 = repo.working_tree_digest();
        assert_ne!(
            d1, d2,
            "content drift under unchanged porcelain must change digest"
        );
        assert_ne!(d2, "dirty-unknown");
        // 确定性：恢复原字节 → digest 回到 d1（不掺 mtime 之类不稳定输入）。
        std::fs::write(repo.resolve("lib.rs"), "fn main() {}\n// marker A\n").unwrap();
        assert_eq!(repo.working_tree_digest(), d1);
    }

    #[test]
    fn clean_digest_equals_write_tree() {
        let repo = init_temp_repo("clean");
        commit_baseline(&repo, "lib.rs", "fn main() {}\n");
        assert_eq!(repo.dirty_state(), Some(false));
        assert_eq!(
            repo.working_tree_digest(),
            repo.git(&["write-tree"]).unwrap()
        );
    }

    #[test]
    fn digest_binds_untracked_content() {
        // EXP5 场景：未跟踪目录整体换内容/换文件名，porcelain 折叠为同一行
        // `?? untracked-exp/`，旧实现 digest 恒不变；新实现必须变。
        let repo = init_temp_repo("untracked");
        commit_baseline(&repo, "lib.rs", "fn main() {}\n");
        let clean = repo.working_tree_digest();
        std::fs::create_dir_all(repo.resolve("untracked-exp")).unwrap();
        std::fs::write(repo.resolve("untracked-exp/a.txt"), "AAAA\n").unwrap();
        let d1 = repo.working_tree_digest();
        assert_ne!(d1, clean);
        std::fs::remove_dir_all(repo.resolve("untracked-exp")).unwrap();
        std::fs::create_dir_all(repo.resolve("untracked-exp")).unwrap();
        std::fs::write(
            repo.resolve("untracked-exp/b.txt"),
            "BBBB different bytes\n",
        )
        .unwrap();
        let d2 = repo.working_tree_digest();
        assert_ne!(d2, d1, "replaced untracked dir must change digest");
        assert_ne!(repo.porcelain_result().unwrap(), String::new());
        // 未跟踪文件消失 → 回到 clean 分支语义。
        std::fs::remove_dir_all(repo.resolve("untracked-exp")).unwrap();
        assert_eq!(repo.working_tree_digest(), clean);
    }

    #[test]
    fn digest_handles_unborn_branch_without_panic() {
        // 边界：无 HEAD（空仓库）。staged + unstaged + untracked 全部存在时
        // 不 panic、digest 为 40 hex、且随各自内容漂移而变。
        let repo = init_temp_repo("unborn");
        std::fs::write(repo.resolve("staged.txt"), "v1\n").unwrap();
        repo.git(&["add", "staged.txt"]).unwrap();
        let d_stage = repo.working_tree_digest();
        assert_eq!(d_stage.len(), 40);
        assert_ne!(d_stage, "dirty-unknown");
        // 改未跟踪文件 → 变
        std::fs::write(repo.resolve("other.txt"), "x\n").unwrap();
        let d_untracked = repo.working_tree_digest();
        assert_ne!(d_untracked, d_stage);
        // 已 staged 文件的工作树再改动（未再 add）→ 也要变（index+diff 叠加兜底）
        std::fs::write(repo.resolve("staged.txt"), "v2\n").unwrap();
        let d_worktree = repo.working_tree_digest();
        assert_ne!(d_worktree, d_untracked);
        // 提交后 HEAD 出现 → clean 分支
        repo.git(&["add", "-A"]).unwrap();
        repo.git(&["commit", "-m", "first"]).unwrap();
        assert_eq!(
            repo.working_tree_digest(),
            repo.git(&["write-tree"]).unwrap()
        );
    }

    #[test]
    fn digest_survives_deleted_and_mode_changed_tracked_files() {
        // 边界：tracked 删除（diff 里是 - 行）与模式变更都不 panic 且可区分。
        let repo = init_temp_repo("delete");
        commit_baseline(&repo, "a.txt", "aaa\n");
        std::fs::write(repo.resolve("b.txt"), "bbb\n").unwrap();
        repo.git(&["add", "b.txt"]).unwrap();
        repo.git(&["commit", "-m", "second"]).unwrap();
        std::fs::remove_file(repo.resolve("a.txt")).unwrap();
        let d_del = repo.working_tree_digest();
        assert_ne!(d_del, repo.git(&["write-tree"]).unwrap_or_default());
        std::fs::write(repo.resolve("a.txt"), "aaa\n").unwrap();
        assert_ne!(repo.working_tree_digest(), d_del);
    }

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
