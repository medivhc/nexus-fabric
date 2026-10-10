//! E4: crash recovery 开机 reconcile（v9 §15.2/§15.3）。
//!
//! 两种模式：
//! - `--victim <state-dir>`：模拟运行中的 daemon——写 1 条未终态 session 记录、
//!   1 条已建立 link marker、run marker，然后 sleep（等 orchestrator kill -9）。
//! - `--json`：orchestrator——起 victim → kill -9 → 两次 nexusd 启动 → 断言 → 输出 JSON。
//!
//! Scenario: `scenarios/product/crash_recovery_boot_reconcile.toml`（冻结期望）。

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nexus_connectivity::{LinkKind, LinkMarker, LinkMarkerStore};
use nexus_domain::{LifecyclePhase, SessionId, TerminalOutcome};
use nexus_session::{SessionRecord, SessionRecordStore};
use nexusd::recovery::{self, FileLinkMarkerStore, FileSessionRecordStore};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fail_json(reason: &str) -> ! {
    println!(
        "{}",
        serde_json::json!({"verdict": "FAIL", "error": reason})
    );
    std::process::exit(1);
}

/// victim：写 crash 前状态，打印 READY，然后睡到被 kill -9。
fn victim(state_dir: &Path) -> ! {
    if let Err(e) = fs::create_dir_all(state_dir) {
        fail_json(&format!("victim: create state dir: {e}"));
    }
    let mut sess = FileSessionRecordStore::new(state_dir);
    if let Err(e) = sess.save(&SessionRecord {
        detached_at_unix: None,
        session: SessionId("s-crash-1".into()),
        phase: LifecyclePhase::Active,
        outcome: TerminalOutcome::Unfinished,
        plan_snapshot: None,
    }) {
        fail_json(&format!("victim: save session: {e}"));
    }
    let mut links = FileLinkMarkerStore::new(state_dir);
    if let Err(e) = links.save(&LinkMarker::established(
        "direct/peer-crash",
        LinkKind::Direct,
        "10.99.99.99:4242",
        now_unix(),
    )) {
        fail_json(&format!("victim: save link: {e}"));
    }
    if let Err(e) = recovery::write_run_marker(state_dir) {
        fail_json(&format!("victim: write run marker: {e}"));
    }
    println!("VICTIM_READY");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn kill(pid: u32, sig: &str) {
    let _ = Command::new("kill").args([sig, &pid.to_string()]).status();
}

/// 等待 victim 打印 VICTIM_READY（15s 超时）。
fn wait_victim_ready(child: &mut Child) {
    let stdout = child.stdout.take().expect("victim stdout piped");
    let mut reader = BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut line = String::new();
    loop {
        line.clear();
        if Instant::now() > deadline {
            fail_json("victim did not print VICTIM_READY in 15s");
        }
        match reader.read_line(&mut line) {
            Ok(0) => fail_json("victim exited before VICTIM_READY"),
            Ok(_) => {
                if line.trim() == "VICTIM_READY" {
                    // 把 stdout 交还（drop reader 即可；child.stdout 已 take，无需归还）
                    return;
                }
            }
            Err(e) => fail_json(&format!("victim stdout read: {e}")),
        }
    }
}

/// 定位预编译的 nexusd binary：与本 example 同一 target dir 下。
/// （`current_exe` 反推在共享 CARGO_TARGET_DIR 下对 workspace 无效，
/// 但对"同一 target dir 下的 binary"有效——example 和 binary 总是在同一 target 里。）
fn nexusd_bin() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let debug_dir = exe.parent()?.parent()?;
    let cand = debug_dir.join("nexusd");
    if cand.exists() {
        return Some(cand);
    }
    let rel = debug_dir.parent()?.join("release").join("nexusd");
    rel.exists().then_some(rel)
}

/// 启动一次 nexusd，等待 boot-reconcile 行 + READY 行，返回 reconcile JSON。
/// stderr 落到 `<config-dir>/nexusd-boot-<tag>.stderr.log`，失败时可取证。
///
/// 超时用 reader 线程 + `recv_timeout` 实现（直接 `read_line` 会在 cargo 编译期
/// 无输出时永久阻塞，deadline 检查不到——2026-10-02 真机踩坑）。
fn boot_nexusd(config_dir: &Path, tag: &str) -> (Child, serde_json::Value) {
    let stderr_path = config_dir.join(format!("nexusd-boot-{tag}.stderr.log"));
    let stderr_file = fs::File::create(&stderr_path)
        .unwrap_or_else(|e| fail_json(&format!("create stderr log: {e}")));

    let mut cmd = match nexusd_bin() {
        Some(bin) => {
            let mut c = Command::new(bin);
            c.arg(config_dir);
            c
        }
        None => {
            // 回退：cargo 现场编译（慢，但自包含）。
            let mut c = Command::new("cargo");
            c.args(["run", "--quiet", "-p", "nexusd", "--bin", "nexusd", "--"])
                .arg(config_dir);
            c
        }
    };
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(stderr_file)
        .spawn()
        .unwrap_or_else(|e| fail_json(&format!("spawn nexusd: {e}")));

    // reader 线程：行 → channel；主线程用 recv_timeout 驱动 deadline。
    enum Ev {
        Line(String),
        Eof,
    }
    let stdout = child.stdout.take().expect("nexusd stdout piped");
    let (tx, rx) = std::sync::mpsc::channel::<Ev>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let _ = tx.send(Ev::Eof);
                    break;
                }
                Ok(_) => {
                    if tx.send(Ev::Line(line.clone())).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = tx.send(Ev::Eof);
                    break;
                }
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(300);
    let mut reconcile: Option<serde_json::Value> = None;
    let mut ready = false;
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            fail_json("nexusd did not print boot-reconcile + READY in 300s");
        }
        // 子进程已退出但还没 READY → 失败（带 stderr 尾巴）。
        if let Ok(Some(_)) = child.try_wait() {
            // 排空剩余行（只为完整性；解析已在主循环完成）
            while rx.try_recv().is_ok() {}
            let tail = fs::read_to_string(&stderr_path)
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let n = lines.len();
                    lines[n.saturating_sub(10)..].join("\n")
                })
                .unwrap_or_default();
            fail_json(&format!("nexusd exited before READY; stderr tail:\n{tail}"));
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ev::Line(t)) => {
                let t = t.trim();
                // 注意：serde_json 默认按 key 字母序输出，行首是 {"crashed_before":…，
                // 不能用 starts_with 匹配 "event"（2026-10-02 真机踩坑）。
                if t.contains("\"event\":\"boot-reconcile\"") {
                    reconcile = serde_json::from_str(t).ok();
                }
                if t.contains("\"verdict\":\"READY\"") {
                    ready = true;
                }
                if ready && reconcile.is_some() {
                    break;
                }
            }
            Ok(Ev::Eof) => continue, // try_wait 分支会处理退出
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => continue,
        }
    }
    (child, reconcile.unwrap())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--victim" {
        victim(Path::new(&args[2]));
    }
    if args.len() != 2 || args[1] != "--json" {
        eprintln!("usage: crash_recovery_e4 --victim <state-dir> | --json");
        std::process::exit(2);
    }

    let tmp = std::env::temp_dir().join(format!("crash-e4-{}", std::process::id()));
    let config_dir = tmp.join("cfg");
    let state_dir = config_dir.join("state");
    fs::create_dir_all(&config_dir).unwrap_or_else(|e| fail_json(&format!("mkdir cfg: {e}")));
    // 最小 network.toml：存在即过 T3 校验；N1 组装失败则降级，不影响 reconcile 断言。
    fs::write(
        config_dir.join("network.toml"),
        "[mesh]\n# crash-recovery e4 minimal\n",
    )
    .unwrap_or_else(|e| fail_json(&format!("write network.toml: {e}")));

    // 1. 起 victim，写 crash 前状态。
    let exe = std::env::current_exe().expect("current_exe");
    let mut victim_child = Command::new(&exe)
        .args(["--victim"])
        .arg(&state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| fail_json(&format!("spawn victim: {e}")));
    wait_victim_ready(&mut victim_child);
    let victim_pid = victim_child.id();

    // 2. kill -9（模拟 SIGKILL / OOM / 掉电）。
    kill(victim_pid, "-9");
    let _ = victim_child.wait();

    // 3. 第一次启动：crash 后的 reconcile。
    let (mut boot1, rec1) = boot_nexusd(&config_dir, "1");
    let boot1_pid = boot1.id();
    // SIGTERM 干净关闭，run marker 应被清除。
    kill(boot1_pid, "-TERM");
    let exited = boot1.wait_timeout_or_kill(Duration::from_secs(15));
    if !exited {
        fail_json("nexusd did not exit on SIGTERM in 15s");
    }
    let marker_gone = !recovery::previous_crashed(&state_dir);

    // 4. 第二次启动：幂等验证。
    let (mut boot2, rec2) = boot_nexusd(&config_dir, "2");
    kill(boot2.id(), "-TERM");
    if !boot2.wait_timeout_or_kill(Duration::from_secs(15)) {
        fail_json("nexusd (2nd boot) did not exit on SIGTERM in 15s");
    }

    // 5. 断言 durable 状态：s-crash-1 必须为 Failed（不静默丢）。
    let sess_file = fs::read_to_string(state_dir.join("sessions.json"))
        .unwrap_or_else(|e| fail_json(&format!("read sessions.json: {e}")));
    let failed_recorded = sess_file.contains("\"s-crash-1\"") && sess_file.contains("\"Failed\"");

    let get = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let get_n = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(999);

    let pass = get(&rec1, "crashed_before")
        && get_n(&rec1, "orphans_classified") == 1
        && get_n(&rec1, "links_staled") == 1
        && failed_recorded
        && marker_gone
        && !get(&rec2, "crashed_before")
        && get_n(&rec2, "orphans_classified") == 0
        && get_n(&rec2, "links_staled") == 0;

    let _ = fs::remove_dir_all(&tmp);
    println!(
        "{}",
        serde_json::json!({
            "verdict": if pass { "PASS" } else { "FAIL" },
            "reconcile": {
                "crashed_before": get(&rec1, "crashed_before"),
                "sessions_checked": get_n(&rec1, "sessions_checked"),
                "orphans_classified": get_n(&rec1, "orphans_classified"),
                "orphan_outcome": if failed_recorded { "Failed" } else { "unknown" },
                "links_checked": get_n(&rec1, "links_checked"),
                "links_staled": get_n(&rec1, "links_staled"),
            },
            "clean_shutdown_cleared_marker": marker_gone,
            "idempotent": {
                "crashed_before": get(&rec2, "crashed_before"),
                "orphans_classified": get_n(&rec2, "orphans_classified"),
                "links_staled": get_n(&rec2, "links_staled"),
            },
        })
    );
}

/// `Child::wait` 带超时，超时则 kill -9；返回是否正常退出。
trait WaitTimeoutOrKill {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> bool;
}

impl WaitTimeoutOrKill for Child {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = self.kill();
                        let _ = self.wait();
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => return false,
            }
        }
    }
}
