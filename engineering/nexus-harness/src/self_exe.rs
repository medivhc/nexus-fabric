//! 稳定自路径（stable self path）。
//!
//! `verify --full` 进程本身就是 `target/debug/nexus-harness`；运行期内任何一次
//! `cargo build -p nexus-harness` 都会把这个文件重链成新 inode，旧映像被 unlink，
//! 之后 `/proc/self/exe` 读出来的是 `<path> (deleted)`，拿它 spawn 自调用子进程必然
//! ENOENT（39 个自调用场景同签名团灭）。
//!
//! 这里在进程启动早期把当前映像固定到**同目录**的私有 hardlink
//! `.nexus-harness-self-<pid>`：cargo 只替换原路径，私有路径仍指向父进程启动时的
//! inode，子进程与父进程字节级同版本。hardlink 不可用时退化为拷贝；两者都失败时
//! 原样使用 `current_exe()`，并由 `verify` 的场景门做 fail-closed 检测（见
//! `replacement_problem`）。
//!
//! 嵌套子进程（`scenario run` 子进程、daemon、mcp selftest 的子进程）同样在启动时
//! 为自己建立一条 pid 命名的链：父进程的私有路径被删除不会影响子进程的自调用。
//! 每条链都由创建者 best-effort 清理；启动时回收同目录里 pid 已不存在的陈旧链。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const BACKUP_PREFIX: &str = ".nexus-harness-self-";

/// 稳定路径的建立方式。`Fallback` 表示 hardlink 与拷贝都失败，`stable` 就是原路径，
/// 因此运行期一旦被重链，自调用仍会失败 —— 此时由 `replacement_problem` 兜底。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hardlink,
    Copy,
    Fallback,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Hardlink => "hardlink",
            Mode::Copy => "copy",
            Mode::Fallback => "fallback",
        }
    }
}

/// 文件身份：Unix 用 (dev, inode)，其他平台退化为 (len, mtime)。
/// 只用于检测"映像是否被替换"，不用于内容等价判断。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    dev: Option<u64>,
    ino: Option<u64>,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

fn identity(path: &Path) -> Option<Identity> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(Identity {
            dev: Some(meta.dev()),
            ino: Some(meta.ino()),
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
    #[cfg(not(unix))]
    {
        Some(Identity {
            dev: None,
            ino: None,
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

#[derive(Debug)]
pub struct SelfExe {
    original: PathBuf,
    stable: PathBuf,
    original_identity: Option<Identity>,
    stable_identity: Option<Identity>,
    mode: Mode,
    owned: bool,
    locate_error: Option<String>,
    establish_error: Option<String>,
}

impl SelfExe {
    pub fn original_path(&self) -> &Path {
        &self.original
    }

    pub fn stable_path(&self) -> &Path {
        &self.stable
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// 自调用失败的真实原因（定位不到自身 / 建立稳定路径失败）。仅在诊断与
    /// `stable_self_exe_checked` 中使用；`Fallback` 本身不阻塞普通命令。
    pub fn locate_error(&self) -> Option<&str> {
        self.locate_error.as_deref()
    }

    pub fn establish_error(&self) -> Option<&str> {
        self.establish_error.as_deref()
    }

    /// 场景门前的 fail-closed 探针：
    /// - 稳定路径建立成功（hardlink/copy）：私有路径必须仍然存在且身份与启动记录一致；
    /// - 回退到原路径：运行映像必须仍是启动时那个 inode，且路径没有 ` (deleted)` 后缀。
    ///
    /// 返回 `Some(诊断)` 表示"带伤运行会产出伪 FAIL"，调用方必须 BLOCKED。
    fn replacement_problem(&self) -> Option<String> {
        if self.mode != Mode::Fallback {
            return self.stable_problem();
        }
        match std::env::current_exe() {
            Ok(live) => self.fallback_problem(&live),
            Err(e) => Some(format!("cannot re-locate own executable: {e}")),
        }
    }

    /// 稳定路径（hardlink/copy）的复查：只依赖启动时记录的私有路径身份，
    /// 不读 `current_exe()` —— 原路径被替换正是预期内的事。
    fn stable_problem(&self) -> Option<String> {
        if let Some(err) = &self.locate_error {
            return Some(format!("cannot locate own executable at startup: {err}"));
        }
        match (identity(&self.stable), self.stable_identity.as_ref()) {
            (Some(current), Some(start)) if &current == start => None,
            (Some(_), Some(_)) => Some(format!(
                "stable self path {} was replaced during the run",
                self.stable.display()
            )),
            _ => Some(format!(
                "stable self path {} disappeared during the run",
                self.stable.display()
            )),
        }
    }

    /// 回退态（stable == original）的复查：运行映像必须还是启动时那个文件。
    /// `live` 由生产调用方传 `current_exe()`；测试传被替换的临时副本路径。
    fn fallback_problem(&self, live: &Path) -> Option<String> {
        if let Some(err) = &self.locate_error {
            return Some(format!("cannot locate own executable at startup: {err}"));
        }
        let live_text = live.to_string_lossy();
        if live_text.ends_with(" (deleted)") {
            return Some(format!(
                "own executable image was unlinked/replaced during the run: {live_text}"
            ));
        }
        match (identity(live), self.original_identity.as_ref()) {
            (Some(live_id), Some(start_id)) if &live_id == start_id => None,
            (Some(_), Some(_)) => Some(format!(
                "own executable image changed identity during the run: {live_text}"
            )),
            _ => Some(format!(
                "cannot stat own executable image to confirm it is unchanged: {live_text}"
            )),
        }
    }
}

fn backup_path(original: &Path, pid: u32) -> Option<PathBuf> {
    let dir = original.parent()?;
    Some(dir.join(format!("{BACKUP_PREFIX}{pid}")))
}

/// 建立稳定路径。`allow_hardlink` / `allow_copy` 仅用于测试模拟降级；
/// 生产路径总是先 hardlink、再拷贝、最后回退。
fn establish_for(original: &Path, pid: u32, allow_hardlink: bool, allow_copy: bool) -> SelfExe {
    let original_identity = identity(original);
    let Some(backup) = backup_path(original, pid) else {
        return SelfExe {
            original: original.to_path_buf(),
            stable: original.to_path_buf(),
            original_identity,
            stable_identity: None,
            mode: Mode::Fallback,
            owned: false,
            locate_error: None,
            establish_error: Some(format!(
                "cannot derive a sibling backup path for {}",
                original.display()
            )),
        };
    };
    // 同一进程重复建立（理论上被 OnceLock 挡住）或 current_exe 已经是自己的备份：
    // 直接复用，不再套娃。
    if backup == original {
        return SelfExe {
            original: original.to_path_buf(),
            stable: original.to_path_buf(),
            original_identity,
            stable_identity: identity(original),
            mode: Mode::Hardlink,
            owned: false,
            locate_error: None,
            establish_error: None,
        };
    }
    // 回收同 pid 的陈旧残留（上一次同 pid 进程崩溃留下的）；此时本进程还没创建它。
    let _ = std::fs::remove_file(&backup);

    let mut establish_error = None;
    if allow_hardlink {
        match std::fs::hard_link(original, &backup) {
            Ok(()) => {
                return SelfExe {
                    original: original.to_path_buf(),
                    stable: backup.clone(),
                    original_identity,
                    stable_identity: identity(&backup),
                    mode: Mode::Hardlink,
                    owned: true,
                    locate_error: None,
                    establish_error: None,
                };
            }
            Err(e) => establish_error = Some(format!("hardlink failed: {e}")),
        }
    }
    if allow_copy {
        match std::fs::copy(original, &backup) {
            Ok(_) => {
                return SelfExe {
                    original: original.to_path_buf(),
                    stable: backup.clone(),
                    original_identity,
                    stable_identity: identity(&backup),
                    mode: Mode::Copy,
                    owned: true,
                    locate_error: None,
                    establish_error,
                };
            }
            Err(e) => {
                let prev = establish_error
                    .take()
                    .map(|p| format!("{p}; "))
                    .unwrap_or_default();
                establish_error = Some(format!("{prev}copy failed: {e}"));
            }
        }
    }
    SelfExe {
        original: original.to_path_buf(),
        stable: original.to_path_buf(),
        original_identity,
        stable_identity: None,
        mode: Mode::Fallback,
        owned: false,
        locate_error: None,
        establish_error,
    }
}

fn unlocatable(error: String) -> SelfExe {
    let fallback = PathBuf::from("nexus-harness");
    SelfExe {
        original: fallback.clone(),
        stable: fallback,
        original_identity: None,
        stable_identity: None,
        mode: Mode::Fallback,
        owned: false,
        locate_error: Some(error),
        establish_error: None,
    }
}

static STATE: OnceLock<SelfExe> = OnceLock::new();

/// main 入口调用。幂等；嵌套子进程同样在启动时建立自己的 pid 命名链。
pub fn init() -> &'static SelfExe {
    STATE.get_or_init(|| {
        let original = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "nexus-harness: self-exe: cannot locate own executable ({e}); \
                     self-invoking scenarios will fail closed"
                );
                return unlocatable(e.to_string());
            }
        };
        if let Some(dir) = original.parent() {
            cleanup_stale(dir);
        }
        let state = establish_for(&original, std::process::id(), true, true);
        if state.mode == Mode::Fallback {
            eprintln!(
                "nexus-harness: self-exe: cannot pin own image next to {} ({}); \
                 falling back to the live path; verify will fail closed if it is replaced",
                original.display(),
                state.establish_error.as_deref().unwrap_or("unknown reason")
            );
        }
        state
    })
}

/// 全部自调用点取这里的路径。
pub fn stable_self_exe() -> PathBuf {
    init().stable.clone()
}

/// 需要显式错误传播的调用点（selftest / daemon）使用：只有"启动时定位不到自身"
/// 才返回 Err；hardlink/拷贝失败的回退路径仍可用，交给 fail-closed 探针兜底。
pub fn stable_self_exe_checked() -> Result<PathBuf, String> {
    let state = init();
    match state.locate_error() {
        Some(e) => Err(e.to_string()),
        None => Ok(state.stable.clone()),
    }
}

/// 场景门前的 fail-closed 探针。稳定路径建立成功时恒为 `None`。
pub fn replacement_problem() -> Option<String> {
    init().replacement_problem()
}

/// 证据里记录建立方式与两条路径（不含密钥，仅路径与 inode 语义）。
pub fn describe_json() -> serde_json::Value {
    let state = init();
    serde_json::json!({
        "mode": state.mode().as_str(),
        "original": state.original_path().to_string_lossy(),
        "stable": state.stable_path().to_string_lossy(),
        "original_identity": identity_json(state.original_identity.as_ref()),
        "stable_identity": identity_json(state.stable_identity.as_ref()),
        "locate_error": state.locate_error(),
        "establish_error": state.establish_error(),
    })
}

fn identity_json(identity: Option<&Identity>) -> serde_json::Value {
    match identity {
        Some(id) => serde_json::json!({
            "dev": id.dev,
            "ino": id.ino,
            "len": id.len,
        }),
        None => serde_json::Value::Null,
    }
}

/// best-effort 清理本进程建立的私有链。父进程退出时子进程已经各自建立自己的链，
/// 因此删除父链不会破坏仍存活的 daemon / scenario 子进程。
pub fn cleanup() {
    let Some(state) = STATE.get() else {
        return;
    };
    if state.owned {
        let _ = std::fs::remove_file(&state.stable);
    }
}

/// 启动时回收同目录的陈旧链：只删除 pid 后缀对应的进程已经不存在的文件。
/// 无法解析 pid 的名字保持不动（宁留垃圾，不误删活进程的映像）。
fn cleanup_stale(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(pid) = name.strip_prefix(BACKUP_PREFIX) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() || process_alive(pid) {
            continue;
        }
        let _ = std::fs::remove_file(entry.path());
    }
}

fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // 无 /proc 的平台无法廉价判定存活：保守地当作存活，留给后续轮次或人工清理。
        let _ = pid;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::process::Command;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nexus-self-exe-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    fn sha256(path: &Path) -> String {
        let bytes = std::fs::read(path).expect("read file for hash");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        format!("{:x}", hasher.finalize())
    }

    fn test_exe_copy(dir: &Path) -> PathBuf {
        let src = dir.join("nexus-harness-under-test");
        std::fs::copy(std::env::current_exe().expect("current_exe"), &src).expect("copy self");
        src
    }

    fn replace_with_other(dir: &Path, target: &Path) {
        let replacement = dir.join("replacement");
        std::fs::write(&replacement, b"this is not the harness binary").expect("write replacement");
        std::fs::rename(&replacement, target).expect("rename over target");
    }

    const CHILD_ENV: &str = "NEXUS_SELF_EXE_TEST_CHILD";

    fn child_probe(dir: &Path, stable: &Path) -> String {
        // libtest 显示的单元测试名（bin crate 的模块路径不带 crate 前缀）。
        let test_name = "self_exe::tests::stable_path_survives_replacement_and_child_is_same_image";
        let out = Command::new(stable)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, dir)
            .output()
            .expect("spawn child from stable path");
        assert!(
            out.status.success(),
            "child from stable path failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// 子进程角色：回显自身映像的哈希，证明它执行的正是父进程启动时的那个 inode。
    fn child_role(dir: &Path) {
        let exe = std::env::current_exe().expect("child current_exe");
        println!(
            "SELF_EXE_CHILD_OK hash={} exe={}",
            sha256(&exe),
            exe.display()
        );
        let _ = dir;
    }

    /// 进程运行中把自身二进制路径 rename 覆盖替换后：稳定路径仍可执行，
    /// 且从它拉起的子进程与父进程启动时是同一份映像（哈希一致）。
    #[test]
    fn stable_path_survives_replacement_and_child_is_same_image() {
        if let Some(dir) = std::env::var_os(CHILD_ENV) {
            child_role(Path::new(&dir));
            return;
        }
        let dir = temp_dir("hardlink");
        let src = test_exe_copy(&dir);
        let before_hash = sha256(&src);
        let state = establish_for(&src, std::process::id() + 1, true, true);
        assert_eq!(state.mode(), Mode::Hardlink, "同目录 hardlink 必须成功");
        assert_ne!(state.stable_path(), src.as_path());
        assert_eq!(
            identity(state.stable_path()),
            state.stable_identity,
            "稳定路径身份必须与启动记录一致"
        );

        replace_with_other(&dir, &src);

        assert!(
            state.stable_problem().is_none(),
            "稳定路径建立成功时 fail-closed 探针必须恒过，实得 {:?}",
            state.stable_problem()
        );
        assert_eq!(sha256(state.stable_path()), before_hash);
        assert_ne!(
            identity(&src),
            state.original_identity,
            "原路径必须确实已被替换（否则本测试没有覆盖到目标场景）"
        );

        let stdout = child_probe(&dir, state.stable_path());
        let line = stdout
            .lines()
            .find(|l| l.contains("SELF_EXE_CHILD_OK"))
            .unwrap_or_else(|| panic!("子进程没有回显身份：{stdout}"));
        assert!(
            line.contains(&before_hash),
            "子进程映像哈希必须等于父进程启动时的哈希：{line}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// hardlink 不可用时退化为拷贝：内容一致、身份独立，替换原路径后仍然可执行。
    #[test]
    fn copy_mode_survives_replacement() {
        let dir = temp_dir("copy");
        let src = test_exe_copy(&dir);
        let before_hash = sha256(&src);
        let state = establish_for(&src, std::process::id() + 2, false, true);
        assert_eq!(state.mode(), Mode::Copy, "hardlink 被禁用时必须走拷贝回退");
        assert_ne!(
            identity(state.stable_path()),
            state.original_identity,
            "拷贝必须产生独立 inode"
        );
        assert_eq!(sha256(state.stable_path()), before_hash);

        replace_with_other(&dir, &src);

        assert!(
            state.stable_problem().is_none(),
            "拷贝回退成功时 fail-closed 探针必须恒过，实得 {:?}",
            state.stable_problem()
        );
        assert_eq!(sha256(state.stable_path()), before_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// hardlink 与拷贝都失败时回退原路径；此时运行期替换必须被探针抓到（fail-closed）。
    #[test]
    fn fallback_mode_detects_replacement() {
        let dir = temp_dir("fallback");
        let src = test_exe_copy(&dir);
        let state = establish_for(&src, std::process::id() + 3, false, false);
        assert_eq!(state.mode(), Mode::Fallback);
        assert_eq!(state.stable_path(), src.as_path());
        assert!(state.fallback_problem(&src).is_none(), "尚未替换时不得误报");

        replace_with_other(&dir, &src);

        let problem = state
            .fallback_problem(&src)
            .expect("原路径被替换后必须被探针抓到");
        assert!(
            problem.contains("identity") || problem.contains("deleted"),
            "诊断必须指出替换事实，实得 {problem}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 嵌套子进程的链必须自然成立：从父进程的私有路径再建立一条 pid 命名的链，
    /// 不报错、不套娃（backup 路径仍是同目录下唯一的 `.nexus-harness-self-<pid>`）。
    #[test]
    fn nested_establishment_chains_once() {
        let dir = temp_dir("nested");
        let src = test_exe_copy(&dir);
        let parent = establish_for(&src, std::process::id() + 4, true, true);
        assert_eq!(parent.mode(), Mode::Hardlink);
        let child = establish_for(parent.stable_path(), std::process::id() + 5, true, true);
        assert_eq!(child.mode(), Mode::Hardlink);
        assert_ne!(child.stable_path(), parent.stable_path());
        assert_eq!(identity(child.stable_path()), parent.stable_identity);
        assert_eq!(
            child
                .stable_path()
                .file_name()
                .map(|n| n.to_string_lossy().to_string()),
            Some(format!("{BACKUP_PREFIX}{}", std::process::id() + 5)),
            "子进程必须使用自己的 pid 命名"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 启动回收只删死 pid 的陈旧链，保留活进程与无法解析的名字。
    #[test]
    fn stale_cleanup_keeps_live_and_unknown_entries() {
        let dir = temp_dir("cleanup");
        let dead = dir.join(format!("{BACKUP_PREFIX}99999999"));
        let live = dir.join(format!("{BACKUP_PREFIX}{}", std::process::id()));
        let unknown = dir.join(format!("{BACKUP_PREFIX}not-a-pid"));
        for p in [&dead, &live, &unknown] {
            std::fs::write(p, b"x").expect("write marker");
        }
        cleanup_stale(&dir);
        assert!(!dead.exists(), "死 pid 的陈旧链必须被回收");
        assert!(live.exists(), "当前进程的链不得被自己回收");
        assert!(unknown.exists(), "无法解析 pid 的名字不得被误删");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
