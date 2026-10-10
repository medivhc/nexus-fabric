//! 自研 daemon：PID 文件、信号处理、退出清理（O2）。
//!
//! - PID 文件防多实例（精确 PID + `kill(pid, 0)` 存活检查；防 pkill 误杀教训）；
//! - SIGTERM/SIGINT → 协作式停机 → 运行 cleanup → 删 PID 文件；
//! - **kill -9 无法清理**（文档明说，见 MODULE.md O2）；
//! - 信号用窄 FFI（`pthread_sigmask`/`sigwait`），不引入 libc crate。

use std::ffi::c_int;
use std::path::{Path, PathBuf};

use nexus_platform::PlatformError;

/// SIGTERM（Linux UAPI `15`）。
const SIGTERM: c_int = 15;
/// SIGINT（Linux UAPI `2`）。
const SIGINT: c_int = 2;
/// `pthread_sigmask` how：`SIG_BLOCK`（`0`）。
const SIG_BLOCK: c_int = 0;

/// `sigset_t`（Linux x86_64：128 字节）。
#[repr(C)]
struct SigSet {
    bits: [u64; 16],
}

unsafe extern "C" {
    fn pthread_sigmask(how: c_int, set: *const SigSet, oldset: *mut SigSet) -> c_int;
    fn sigwait(set: *const SigSet, sig: *mut c_int) -> c_int;
    fn sigemptyset(set: *mut SigSet) -> c_int;
    fn sigaddset(set: *mut SigSet, signum: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
}

/// 构造只含 SIGTERM/SIGINT 的 sigset（纯逻辑）。
fn term_set() -> SigSet {
    let mut set = SigSet { bits: [0; 16] };
    // SAFETY：set 为有效可写指针。
    unsafe {
        sigemptyset(&mut set);
        sigaddset(&mut set, SIGTERM);
        sigaddset(&mut set, SIGINT);
    }
    set
}

/// 阻塞 SIGTERM/SIGINT（调用线程及之后创建的线程继承掩码）。
fn block_term_signals() {
    let set = term_set();
    // SAFETY：set 为有效只读指针；oldset=NULL。
    unsafe {
        pthread_sigmask(SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// 检查 PID 是否存活（`kill(pid, 0)`，纯 FFI 包装）。
fn pid_alive(pid: c_int) -> bool {
    // SAFETY：sig=0 不发送信号，只做存活检查。
    unsafe { kill(pid, 0) == 0 }
}

/// 读取 PID 文件中的 PID（纯函数）。
fn read_pid_file(path: &Path) -> Option<c_int> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<c_int>()
        .ok()
}

/// daemon 守卫：持有 PID 文件，Drop 时删文件。
///
/// 典型用法：
/// ```ignore
/// let daemon = Daemon::acquire("/run/nexus-os-assemble.pid")?;
/// daemon.run_until_signal(|| { /* 清理：删地址/路由 */ });
/// ```
pub struct Daemon {
    pid_path: PathBuf,
    /// 是否已释放（防 Drop 重复删）。
    released: bool,
}

impl Daemon {
    /// 获取 daemon 身份（PID 文件）：
    /// - 文件存在且 PID 存活 → `AlreadyRunning` 错误；
    /// - 文件存在但 PID 已死（stale）→ 覆盖；
    /// - 写入当前 PID。
    pub fn acquire(pid_path: &Path) -> Result<Self, PlatformError> {
        if let Some(pid) = read_pid_file(pid_path) {
            if pid_alive(pid) {
                return Err(PlatformError::Io {
                    operation: format!("daemon acquire {}", pid_path.display()),
                    message: format!("already running (pid {pid})"),
                });
            }
            // stale：继续覆盖。
        }
        let me = std::process::id() as c_int;
        std::fs::write(pid_path, format!("{me}\n")).map_err(|e| PlatformError::Io {
            operation: format!("daemon write pid {}", pid_path.display()),
            message: e.to_string(),
        })?;
        // 阻塞信号，后续线程继承；主线程用 sigwait 等待。
        block_term_signals();
        Ok(Daemon {
            pid_path: pid_path.to_path_buf(),
            released: false,
        })
    }

    /// 阻塞等待 SIGTERM/SIGINT，收到后运行 `cleanup`，再释放 PID 文件。
    ///
    /// `cleanup` 只运行一次；其错误被记录为返回值（调用方可告警）。
    pub fn run_until_signal(
        self,
        cleanup: impl FnOnce() -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        let set = term_set();
        let mut sig: c_int = 0;
        // SAFETY：set/sig 为有效指针；sigwait 同步等待。
        let rc = unsafe { sigwait(&set, &mut sig) };
        let mut this = self;
        let cleanup_result = cleanup();
        this.release();
        if rc != 0 {
            return Err(PlatformError::Io {
                operation: "daemon sigwait".into(),
                message: format!("sigwait failed: {rc}"),
            });
        }
        let _ = sig;
        cleanup_result
    }

    /// 释放 PID 文件（幂等）。
    pub fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // 只删自己写的（校验 PID 一致，防误删）。
        if read_pid_file(&self.pid_path) == Some(std::process::id() as c_int) {
            let _ = std::fs::remove_file(&self.pid_path);
        }
    }

    /// PID 文件路径。
    #[must_use]
    pub fn pid_path(&self) -> &Path {
        &self.pid_path
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_set_contains_term_and_int() {
        // 纯逻辑：构造不 panic；位图非零。
        let set = term_set();
        assert!(set.bits.iter().any(|&b| b != 0));
    }

    #[test]
    fn read_pid_file_parses_pid() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nexus-test-{}.pid", std::process::id()));
        std::fs::write(&path, "12345\n").unwrap();
        assert_eq!(read_pid_file(&path), Some(12345));
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_pid_file(&path), None);
        std::fs::write(&path, "not-a-pid\n").unwrap();
        assert_eq!(read_pid_file(&path), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn acquire_and_release_pid_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nexus-test-acquire-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut d = Daemon::acquire(&path).expect("acquire");
            assert_eq!(read_pid_file(&path), Some(std::process::id() as c_int));
            // 第二次 acquire → AlreadyRunning（自己还活着）。
            let r = Daemon::acquire(&path);
            assert!(r.is_err());
            d.release();
        }
        assert_eq!(read_pid_file(&path), None);
    }

    #[test]
    fn acquire_overwrites_stale_pid_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nexus-test-stale-{}.pid", std::process::id()));
        // 写一个极大概率不存在的 PID。
        std::fs::write(&path, "999999999\n").unwrap();
        let mut d = Daemon::acquire(&path).expect("stale should be overwritten");
        assert_eq!(read_pid_file(&path), Some(std::process::id() as c_int));
        d.release();
    }
}
