//! E4: nexusd Workspace 生产接线端到端验证（`product.daemon-workspace-mount`）。
//!
//! 拉起真实 `nexusd` 子进程（隔离临时 config dir），按序验证 7 个冻结期望：
//! mount → 内核读写 → LocalAPI commit（Head 前进）→ SIGTERM 优雅关闭（已卸载）
//! → 重启重开（Head 一致、文件可读）→ kill -9 后 orphan mount 清理 →
//! D5：脏数据不静默提交（Head 不变 + daemon stderr 有 WARN）。
//!
//! 无 `/dev/fuse` → `verdict=SKIP`（D8）。verdict 始终打 JSON 到 stdout，exit 0。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// C1 专用 LocalAPI 端口（与 C2/C3 真机并行 E4 隔离）。
const LOCALAPI_ADDR: &str = "127.0.0.1:18081";
const WS_ID: &str = "e4ws";

#[derive(Debug)]
enum Fail {
    Skip(String),
    Fail(String),
}

type R<T> = Result<T, Fail>;

fn main() {
    let outcome = run_e4();
    let json = match outcome {
        Ok(detail) => serde_json::json!({
            "verdict": "PASS",
            "mount_ok": true,
            "kernel_write_read_ok": true,
            "commit_advances_head": true,
            "graceful_shutdown_unmounted": true,
            "restart_reopens_workspace": true,
            "orphan_mount_cleaned": true,
            "no_implicit_commit": true,
            "detail": detail,
        }),
        Err(Fail::Skip(reason)) => serde_json::json!({
            "verdict": "SKIP",
            "reason": reason,
        }),
        Err(Fail::Fail(detail)) => serde_json::json!({
            "verdict": "FAIL",
            "detail": detail,
        }),
    };
    println!("{json}");
}

// Fail 有两种形态：用元组变体表达。
impl Fail {
    fn skip(reason: impl Into<String>) -> Self {
        Fail::Skip(reason.into())
    }
    fn failure(detail: impl Into<String>) -> Self {
        Fail::Fail(detail.into())
    }
    #[allow(dead_code)]
    fn is_skip(&self) -> bool {
        matches!(self, Fail::Skip(_))
    }
    #[allow(dead_code)]
    fn msg(&self) -> &str {
        match self {
            Fail::Skip(s) | Fail::Fail(s) => s,
        }
    }
}

fn check(cond: bool, msg: &str) -> R<()> {
    if cond {
        Ok(())
    } else {
        Err(Fail::failure(msg))
    }
}

/// 最小 HTTP GET（裸 TcpStream；只取 body）。
fn http_get(path: &str) -> R<String> {
    let mut s = std::net::TcpStream::connect(LOCALAPI_ADDR)
        .map_err(|e| Fail::failure(format!("localapi connect: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Fail::failure(format!("set timeout: {e}")))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")
        .map_err(|e| Fail::failure(format!("http write: {e}")))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)
        .map_err(|e| Fail::failure(format!("http read: {e}")))?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .ok_or_else(|| Fail::failure(format!("bad http response: {text:?}")))
}

fn http_get_json(path: &str) -> R<serde_json::Value> {
    let body = http_get(path)?;
    serde_json::from_str(&body).map_err(|e| Fail::failure(format!("bad json from {path}: {e}")))
}

fn is_mounted(mountpoint: &Path) -> bool {
    let target = mountpoint.to_string_lossy();
    std::fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mp| mp == target)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // apps/nexusd
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("workspace root")
}

fn nexusd_bin() -> R<PathBuf> {
    let root = workspace_root();
    // 先确保 binary 已构建（example 构建时 bin target 不一定在）。
    let st = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("-p")
        .arg("nexusd")
        .arg("--bin")
        .arg("nexusd")
        .current_dir(&root)
        .status()
        .map_err(|e| Fail::failure(format!("cargo build nexusd: {e}")))?;
    check(st.success(), "cargo build -p nexusd --bin nexusd failed")?;
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target"));
    let bin = target_dir.join("debug").join("nexusd");
    check(
        bin.is_file(),
        &format!("nexusd binary missing: {}", bin.display()),
    )?;
    Ok(bin)
}

struct Daemon {
    child: Child,
    stderr_path: PathBuf,
}

impl Daemon {
    fn spawn(bin: &Path, config_dir: &Path, stderr_path: PathBuf) -> R<Self> {
        let err_file = std::fs::File::create(&stderr_path)
            .map_err(|e| Fail::failure(format!("create stderr file: {e}")))?;
        let child = Command::new(bin)
            .arg(config_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(err_file))
            .spawn()
            .map_err(|e| Fail::failure(format!("spawn nexusd: {e}")))?;
        Ok(Self { child, stderr_path })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// 等 LocalAPI 就绪且 workspace 已挂载（子进程早死则早失败）。
    fn wait_ready(&mut self, expect_mounts: usize) -> R<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    return Err(Fail::failure(format!(
                        "daemon exited early: {status}; stderr: {}",
                        self.stderr_text().chars().take(2000).collect::<String>()
                    )));
                }
                Ok(None) => {}
                Err(e) => return Err(Fail::failure(format!("try_wait: {e}"))),
            }
            if let Ok(v) = http_get_json("/localapi/v0/workspace/mounts") {
                let n = v
                    .get("mounts")
                    .and_then(|m| m.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                if n >= expect_mounts {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                return Err(Fail::failure(format!(
                    "timeout waiting for daemon LocalAPI/mounts; stderr: {}",
                    self.stderr_text().chars().take(2000).collect::<String>()
                )));
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    fn term(&mut self) -> R<()> {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.pid().to_string())
            .status();
        Ok(())
    }

    fn kill9(&mut self) -> R<()> {
        let _ = Command::new("kill")
            .arg("-9")
            .arg(self.pid().to_string())
            .status();
        Ok(())
    }

    fn wait_exit(&mut self, timeout: Duration) -> R<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {
                    if Instant::now() > deadline {
                        return Err(Fail::failure("timeout waiting for daemon exit"));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(Fail::failure(format!("try_wait: {e}"))),
            }
        }
    }

    fn stderr_text(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

fn run_e4() -> Result<String, Fail> {
    // D8：无 /dev/fuse → SKIP（不判 FAIL）。
    if !Path::new("/dev/fuse").exists() {
        return Err(Fail::skip("no /dev/fuse (D8: warn + disabled)"));
    }

    let bin = nexusd_bin()?;
    let base = std::env::temp_dir().join(format!("daemon-ws-e4-{}", std::process::id()));
    let config_dir = base.join("config");
    let mountpoint = base.join("mnt");
    std::fs::create_dir_all(&config_dir).map_err(|e| Fail::failure(format!("mkdir: {e}")))?;
    // 隔离：C1 专用端口 + no-tun（本 E4 不需要网络面）。
    std::fs::write(
        config_dir.join("daemon.toml"),
        "localapi_addr = \"127.0.0.1:18081\"\n[tun]\nenabled = false\n",
    )
    .map_err(|e| Fail::failure(format!("write daemon.toml: {e}")))?;
    std::fs::write(
        config_dir.join("workspace.toml"),
        format!(
            "[[workspace]]\nid = \"{WS_ID}\"\nmountpoint = \"{}\"\nauthor = \"e4\"\n",
            mountpoint.display()
        ),
    )
    .map_err(|e| Fail::failure(format!("write workspace.toml: {e}")))?;

    // 清理守卫：杀残留子进程、卸挂载、删临时目录。
    struct Guard {
        base: PathBuf,
        mountpoint: PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            for bin in ["fusermount", "fusermount3"] {
                let _ = Command::new(bin).arg("-u").arg(&self.mountpoint).output();
            }
            std::fs::remove_dir_all(&self.base).ok();
        }
    }
    let _guard = Guard {
        base: base.clone(),
        mountpoint: mountpoint.clone(),
    };

    // ---- 阶段 1：启动 → 挂载 ----
    let mut d1 = Daemon::spawn(&bin, &config_dir, base.join("d1.stderr"))?;
    d1.wait_ready(1)?;
    check(
        is_mounted(&mountpoint),
        "mount_ok: mountpoint not in /proc/mounts",
    )?;

    // ---- 内核读写 ----
    let f1 = mountpoint.join("f1.txt");
    std::fs::write(&f1, b"hello-workspace")
        .map_err(|e| Fail::failure(format!("kernel write: {e}")))?;
    let back = std::fs::read(&f1).map_err(|e| Fail::failure(format!("kernel read: {e}")))?;
    check(
        back == b"hello-workspace",
        "kernel_write_read_ok: bytes mismatch",
    )?;

    // ---- commit 前进 Head ----
    let head_before = http_get_json("/localapi/v0/workspace/mounts")?
        .get("mounts")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("head"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Fail::failure("no head in mounts status"))?;
    std::fs::write(mountpoint.join("f2.txt"), b"second")
        .map_err(|e| Fail::failure(format!("write f2: {e}")))?;
    let commit_resp = http_get_json(&format!("/localapi/v0/workspace/commit/{WS_ID}"))?;
    let head_after = commit_resp
        .get("head")
        .and_then(|h| h.as_str())
        .ok_or_else(|| Fail::failure(format!("commit bad response: {commit_resp}")))?;
    check(
        head_after != head_before,
        "commit_advances_head: head did not advance",
    )?;
    // FUSE 侧 head() 与 LocalAPI 一致。
    let head_api = http_get_json("/localapi/v0/workspace/mounts")?
        .get("mounts")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("head"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    check(
        head_api == head_after,
        "commit_advances_head: FUSE head != LocalAPI head",
    )?;

    // ---- D5：写脏数据但不提交，然后 SIGTERM ----
    std::fs::write(mountpoint.join("f3-dirty.txt"), b"dirty")
        .map_err(|e| Fail::failure(format!("write f3: {e}")))?;
    d1.term()?;
    d1.wait_exit(Duration::from_secs(20))?;
    check(
        !is_mounted(&mountpoint),
        "graceful_shutdown_unmounted: still mounted after SIGTERM",
    )?;
    let stderr1 = d1.stderr_text();
    check(
        stderr1.contains("has uncommitted changes"),
        "shutdown should WARN on uncommitted changes (D5)",
    )?;

    // ---- 阶段 2：重启 → 重开 ----
    let mut d2 = Daemon::spawn(&bin, &config_dir, base.join("d2.stderr"))?;
    d2.wait_ready(1)?;
    let mounts2 = http_get_json("/localapi/v0/workspace/mounts")?;
    let head2 = mounts2
        .get("mounts")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("head"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    // D5：脏数据未被静默提交 → Head 与 commit 后一致。
    check(
        head2 == head_after,
        &format!("no_implicit_commit: head changed across restart ({head_after} -> {head2})"),
    )?;
    // 持久化验证：f1/f2 可读（FsContentStore + state_root）。
    let r1 = std::fs::read(mountpoint.join("f1.txt"))
        .map_err(|e| Fail::failure(format!("reopen read f1: {e}")))?;
    let r2 = std::fs::read(mountpoint.join("f2.txt"))
        .map_err(|e| Fail::failure(format!("reopen read f2: {e}")))?;
    check(
        r1 == b"hello-workspace" && r2 == b"second",
        "restart_reopens_workspace: file bytes mismatch after reopen",
    )?;

    // ---- 阶段 3：kill -9 → orphan 清理 ----
    d2.kill9()?;
    d2.wait_exit(Duration::from_secs(10))?;
    // orphan 挂载残留（kill -9 不走优雅关闭）。
    let orphaned = is_mounted(&mountpoint);
    let mut d3 = Daemon::spawn(&bin, &config_dir, base.join("d3.stderr"))?;
    d3.wait_ready(1)?;
    check(
        is_mounted(&mountpoint),
        "orphan_mount_cleaned: not mounted after restart",
    )?;
    // 挂载点只有一个挂载项（没有重复挂载）。
    let target = mountpoint.to_string_lossy().into_owned();
    let count = std::fs::read_to_string("/proc/mounts")
        .map(|t| {
            t.lines()
                .filter(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .map(|m| m == target)
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);
    check(
        count == 1,
        &format!("orphan_mount_cleaned: expected 1 mount entry, got {count}"),
    )?;
    let head3 = http_get_json("/localapi/v0/workspace/mounts")?
        .get("mounts")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("head"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    check(
        head3 == head_after,
        "orphan_mount_cleaned: head changed after kill -9 restart",
    )?;
    d3.term()?;
    d3.wait_exit(Duration::from_secs(20))?;

    let detail = format!(
        "3 daemon lifecycles; orphaned_after_kill9={orphaned}; heads consistent ({head_after})"
    );
    Ok(detail)
}
