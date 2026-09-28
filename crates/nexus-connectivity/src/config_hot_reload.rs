//! 配置热加载（内存骨架，纯逻辑）。
//!
//! 本模块是 delivery 层共享底座的配置热加载骨架：
//! - **配置**：`HotReloadConfig` 持有轮询间隔 / 是否在应用前校验；
//! - **结果**：`ReloadResult` 二态（Success 携带已应用 revision / Failed 携带原因）；
//! - **管理器**：`HotReloadManager` 记录当前已生效 revision，按提议决定是否应用；
//! - **决策规则**：`validate_before_apply=true` 且候选 `valid=false` → Failed，
//!   当前 revision 不变；否则把当前 revision 推进到候选 revision。
//!
//! 边界（PRODUCT §12-config-hot-reload 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不监听真实文件、不解析真实配置；
//! - 不引入 `notify-debouncer` 等外部 watcher crate；
//! - revision 是单调递增的版本号（调用方保证其单调），本模块只做比较与推进；
//! - 真实文件 watcher 线程 / 真实配置解析留 TODO。
//!
//! TODO（真实热加载集成，非本骨架范围）：
//! - 起一个有 Owner 的文件 watcher 任务（CancellationToken + JoinSet），
//!   按 `watch_interval_ms` 轮询或 inotify 监听配置文件变化；
//! - 重新解析配置并产出结构化校验结果（`valid`），再提交给本管理器；
//! - 应用新配置时做原子切换（先校验通过，再原子替换当前生效版本）；
//! - 暴露指标（热加载次数 / 校验失败次数）到可观测层。
//!
//! 错误面独立：`HotReloadError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 配置热加载相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotReloadError {
    /// 配置非法（如 watch_interval_ms=0）。
    InvalidConfig(String),
    /// 文件 I/O 错误（读取 / metadata 失败，或内容非 UTF-8）。
    Io(String),
}

impl fmt::Display for HotReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => {
                write!(f, "HOT_RELOAD_INVALID_CONFIG: {msg}")
            }
            Self::Io(msg) => {
                write!(f, "HOT_RELOAD_IO: {msg}")
            }
        }
    }
}

impl std::error::Error for HotReloadError {}

// ---------- 热加载结果 ----------

/// 一次热加载提议的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadResult {
    /// 应用成功，携带新生效的 revision。
    Success {
        /// 本次实际应用的配置 revision。
        applied_revision: u64,
    },
    /// 应用失败，携带结构化原因。
    Failed {
        /// 失败原因（如校验未通过）。
        reason: String,
    },
}

impl ReloadResult {
    /// 返回稳定的小写字符串标签（供 JSON / 日志 / 断言使用）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success { .. } => "success",
            Self::Failed { .. } => "failed",
        }
    }
}

impl fmt::Display for ReloadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success { applied_revision } => {
                write!(f, "reload success (revision={applied_revision})")
            }
            Self::Failed { reason } => {
                write!(f, "reload failed: {reason}")
            }
        }
    }
}

// ---------- 配置 ----------

/// 热加载配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotReloadConfig {
    /// 配置文件轮询间隔（毫秒，逻辑时钟；必须 > 0）。
    pub watch_interval_ms: u64,
    /// 应用前是否校验候选配置（true 时校验失败拒绝应用）。
    pub validate_before_apply: bool,
}

impl HotReloadConfig {
    /// 构造配置并校验不变量。
    ///
    /// 校验：
    /// - `watch_interval_ms > 0`。
    ///
    /// 非法返回 `HotReloadError::InvalidConfig`。
    pub fn new(
        watch_interval_ms: u64,
        validate_before_apply: bool,
    ) -> Result<Self, HotReloadError> {
        if watch_interval_ms == 0 {
            return Err(HotReloadError::InvalidConfig(
                "watch_interval_ms must be > 0".to_string(),
            ));
        }
        Ok(Self {
            watch_interval_ms,
            validate_before_apply,
        })
    }
}

// ---------- 管理器 ----------

/// 配置热加载管理器：记录当前已生效 revision，按提议决定是否应用。
///
/// 纯内存、纯同步；不监听文件、不解析配置，只做"校验门控 + revision 推进"。
pub struct HotReloadManager {
    cfg: HotReloadConfig,
    /// 当前已生效的配置 revision（初始为 0）。
    current_revision: u64,
}

impl HotReloadManager {
    /// 用给定配置构造管理器，初始 revision 为 0。
    #[must_use]
    pub fn new(cfg: HotReloadConfig) -> Self {
        Self {
            cfg,
            current_revision: 0,
        }
    }

    /// 提议应用一个新 revision 的配置。
    ///
    /// 决策：
    /// - `validate_before_apply=true` 且 `valid=false` → `Failed`，当前 revision 不变；
    /// - 否则把当前 revision 推进到 `new_revision`，返回 `Success { applied_revision }`。
    pub fn propose_reload(&mut self, new_revision: u64, valid: bool) -> ReloadResult {
        if self.cfg.validate_before_apply && !valid {
            return ReloadResult::Failed {
                reason: "proposed configuration failed validation".to_string(),
            };
        }
        self.current_revision = new_revision;
        ReloadResult::Success {
            applied_revision: new_revision,
        }
    }

    /// 当前已生效的配置 revision（只读）。
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.current_revision
    }
}

// === 12.40.6 配置文件 std 轮询 watcher（不引入 notify crate） ===================

use std::path::{Path, PathBuf};

/// std 文件轮询 watcher：按内容指纹（长度 + FNV-1a 哈希）判断配置文件是否变化。
///
/// 不引入 `notify`/`notify-debouncer`；调用方按 `watch_interval_ms` 周期主动调
/// `poll_changed()`，变化后 `read_current()` 取内容并自行校验，再喂给
/// `HotReloadManager::propose_reload`。
pub struct FileWatcher {
    path: PathBuf,
    last_len: Option<u64>,
    last_hash: Option<u64>,
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

impl FileWatcher {
    /// 绑定一个配置文件路径；首次 `poll_changed()` 建立基线（返回 false）。
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            last_len: None,
            last_hash: None,
        }
    }

    fn fingerprint(&self) -> Result<(u64, u64), HotReloadError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| HotReloadError::Io(format!("read {:?}: {e}", self.path)))?;
        Ok((bytes.len() as u64, fnv1a(&bytes)))
    }

    /// 轮询一次；相对上次指纹（长度或内容哈希）变化即返回 `Ok(true)`。
    /// 首次调用为基线，返回 `Ok(false)`。
    pub fn poll_changed(&mut self) -> Result<bool, HotReloadError> {
        let (len, hash) = self.fingerprint()?;
        let changed = match (self.last_len, self.last_hash) {
            (Some(l), Some(h)) => l != len || h != hash,
            (None, None) => false,
            _ => true,
        };
        self.last_len = Some(len);
        self.last_hash = Some(hash);
        Ok(changed)
    }

    /// 读取文件当前内容（UTF-8）。
    pub fn read_current(&self) -> Result<String, HotReloadError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| HotReloadError::Io(format!("read {:?}: {e}", self.path)))?;
        String::from_utf8(bytes)
            .map_err(|_| HotReloadError::Io("config file is not valid utf-8".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(validate: bool) -> HotReloadConfig {
        HotReloadConfig::new(1_000, validate).expect("valid config")
    }

    #[test]
    fn config_accepts_valid_values() {
        let c = HotReloadConfig::new(1_000, true).expect("valid");
        assert_eq!(c.watch_interval_ms, 1_000);
        assert!(c.validate_before_apply);
    }

    #[test]
    fn config_rejects_zero_interval() {
        let err = HotReloadConfig::new(0, true).expect_err("interval must be > 0");
        assert!(matches!(err, HotReloadError::InvalidConfig(_)));
    }

    #[test]
    fn starts_at_revision_zero() {
        let m = HotReloadManager::new(cfg(true));
        assert_eq!(m.current_revision(), 0);
    }

    #[test]
    fn valid_proposal_applies_and_advances_revision() {
        let mut m = HotReloadManager::new(cfg(true));
        let r = m.propose_reload(7, true);
        assert_eq!(
            r,
            ReloadResult::Success {
                applied_revision: 7
            }
        );
        assert_eq!(r.as_str(), "success");
        assert_eq!(m.current_revision(), 7);
    }

    #[test]
    fn invalid_proposal_rejected_when_validate_on() {
        let mut m = HotReloadManager::new(cfg(true));
        m.propose_reload(7, true);
        let r = m.propose_reload(9, false);
        assert!(matches!(r, ReloadResult::Failed { .. }));
        assert_eq!(r.as_str(), "failed");
        // 当前 revision 保持不变。
        assert_eq!(m.current_revision(), 7);
    }

    #[test]
    fn invalid_proposal_applies_when_validate_off() {
        let mut m = HotReloadManager::new(cfg(false));
        m.propose_reload(7, true);
        // 关闭前置校验时，即使 valid=false 也直接应用。
        let r = m.propose_reload(9, false);
        assert_eq!(
            r,
            ReloadResult::Success {
                applied_revision: 9
            }
        );
        assert_eq!(m.current_revision(), 9);
    }

    #[test]
    fn rejected_proposal_does_not_block_later_valid_one() {
        let mut m = HotReloadManager::new(cfg(true));
        m.propose_reload(1, true);
        let bad = m.propose_reload(2, false);
        assert!(matches!(bad, ReloadResult::Failed { .. }));
        let good = m.propose_reload(3, true);
        assert_eq!(
            good,
            ReloadResult::Success {
                applied_revision: 3
            }
        );
        assert_eq!(m.current_revision(), 3);
    }

    #[test]
    fn reload_result_as_str_and_display() {
        assert_eq!(
            ReloadResult::Success {
                applied_revision: 1
            }
            .as_str(),
            "success"
        );
        assert_eq!(
            ReloadResult::Failed { reason: "x".into() }.as_str(),
            "failed"
        );
        assert!(
            ReloadResult::Success {
                applied_revision: 1
            }
            .to_string()
            .contains("revision=1")
        );
        assert!(
            ReloadResult::Failed {
                reason: "boom".into()
            }
            .to_string()
            .contains("boom")
        );
    }

    #[test]
    fn error_display_is_structured() {
        let e = HotReloadError::InvalidConfig("bad interval".into());
        assert!(e.to_string().contains("bad interval"));
    }

    // ---- FileWatcher std 轮询测试（临时文件） ----

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        std::env::temp_dir().join(format!("nexus-watch-{pid}-{tag}.txt"))
    }

    #[test]
    fn filewatcher_baseline_then_change_then_unchanged() {
        let p = tmp_path("baseline");
        std::fs::write(&p, "v1").unwrap();
        let mut w = FileWatcher::new(&p);
        // 首次 = 基线。
        assert!(!w.poll_changed().unwrap());
        // 内容变化。
        std::fs::write(&p, "v2-changed").unwrap();
        assert!(w.poll_changed().unwrap());
        // 内容未变。
        assert!(!w.poll_changed().unwrap());
        // 读回当前内容。
        assert_eq!(w.read_current().unwrap(), "v2-changed");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn filewatcher_missing_file_is_io() {
        let p = tmp_path("does-not-exist");
        let _ = std::fs::remove_file(&p);
        let mut w = FileWatcher::new(&p);
        let err = w.poll_changed().expect_err("missing file");
        assert!(matches!(err, HotReloadError::Io(_)));
    }

    #[test]
    fn filewatcher_non_utf8_is_io() {
        let p = tmp_path("non-utf8");
        std::fs::write(&p, [0xffu8, 0xfe, 0x00, 0x01]).unwrap();
        let mut w = FileWatcher::new(&p);
        w.poll_changed().unwrap(); // baseline ok
        let err = w.read_current().expect_err("non-utf8");
        assert!(matches!(err, HotReloadError::Io(_)));
        std::fs::remove_file(&p).ok();
    }
}
