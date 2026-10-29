//! 日志级别控制（内存骨架，纯逻辑）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的日志级别查询 / 覆盖骨架：
//! - **级别**：`LogLevel` 五档（Error/Warn/Info/Debug/Trace），带小写字符串往返与严重度排序；
//! - **配置**：`LogLevelConfig` 持有全局级别 + 模块覆盖表（`module -> LogLevel`）；
//! - **控制器**：`LogLevelController` 按"模块覆盖优先、否则回退全局"给出某模块的有效级别，
//!   并按严重度阈值判断某条日志是否应输出；
//! - **热加载门控**：`propose` 接受新配置并二态返回 `LevelApplyResult`（Applied/Rejected），
//!   本骨架简化为总是 Applied 并直接应用。
//!
//! 边界（PRODUCT §12-log-level 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不接 `tracing`/`log` crate，不做任何真实输出；
//! - 严重度约定：`Error=0 < Warn=1 < Info=2 < Debug=3 < Trace=4`；
//!   一条日志 `enabled` 当且仅当其 severity <= 该模块有效级别的 severity
//!   （即更重要或同级才打印）；
//! - 模块名按字符串精确匹配覆盖表；无通配 / 前缀匹配。
//!
//! TODO（真实日志接入，非本骨架范围）：
//! - 把 `effective_level` 接到 `tracing` 的 per-module filter（`EnvFilter` /
//!   `Targets`），实现运行时动态刷新；
//! - `propose` 接入真实配置校验（级别字符串合法性、模块名白名单），失败时返回 Rejected；
//! - 暴露指标（当前全局级别、覆盖条目数、被过滤日志计数）到可观测层。
//!
//! 错误面独立：`LogLevelError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::fmt;

// ---------- 错误 ----------

/// 日志级别相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevelError {
    /// 无法把字符串解析为合法级别。
    InvalidLevel {
        /// 非法的级别字符串（人可读）。
        raw: String,
    },
}

impl fmt::Display for LogLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLevel { raw } => {
                write!(f, "LOG_LEVEL_INVALID: cannot parse level {raw:?}")
            }
        }
    }
}

impl std::error::Error for LogLevelError {}

// ---------- 级别 ----------

/// 日志严重级别（五档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// 错误（最严重，severity=0）。
    Error,
    /// 警告（severity=1）。
    Warn,
    /// 信息（severity=2）。
    Info,
    /// 调试（severity=3）。
    Debug,
    /// 跟踪（最详细，severity=4）。
    Trace,
}

impl LogLevel {
    /// 返回稳定的小写字符串标签（"error"/"warn"/"info"/"debug"/"trace"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// 严重度数值：Error=0 ... Trace=4。数值越大越详细。
    #[must_use]
    pub fn severity(&self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = LogLevelError;

    /// 大小写不敏感解析级别字符串；非法返回 `LogLevelError::InvalidLevel`。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(LogLevelError::InvalidLevel { raw: s.to_string() }),
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 日志级别配置：全局级别 + 按模块覆盖表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLevelConfig {
    /// 全局默认级别（未命中覆盖表时使用）。
    pub global: LogLevel,
    /// 模块名 → 覆盖级别（精确匹配）。
    pub module_overrides: HashMap<String, LogLevel>,
}

impl LogLevelConfig {
    /// 构造配置，覆盖表为空。
    #[must_use]
    pub fn new(global: LogLevel) -> Self {
        Self {
            global,
            module_overrides: HashMap::new(),
        }
    }

    /// 设置（或覆盖）某模块的级别。
    pub fn set_module(&mut self, module: String, level: LogLevel) {
        self.module_overrides.insert(module, level);
    }
}

// ---------- 热加载门控结果 ----------

/// 一次级别配置热加载提议的结果（Applied / Rejected 二态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LevelApplyResult {
    /// 应用成功，携带新生效的全局级别。
    Applied {
        /// 本次应用后的全局级别。
        global: LogLevel,
    },
    /// 应用失败，携带结构化原因。
    Rejected {
        /// 失败原因（如校验未通过）。
        reason: String,
    },
}

impl LevelApplyResult {
    /// 返回稳定的小写字符串标签（供 JSON / 日志 / 断言使用）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::Rejected { .. } => "rejected",
        }
    }
}

// ---------- 控制器 ----------

/// 日志级别控制器：持有当前配置，提供有效级别查询与动态调整。
///
/// 纯内存、纯同步；不接真实日志后端，只做"覆盖查表 + 严重度阈值判断"。
pub struct LogLevelController {
    config: LogLevelConfig,
}

impl LogLevelController {
    /// 用给定配置构造控制器。
    #[must_use]
    pub fn new(config: LogLevelConfig) -> Self {
        Self { config }
    }

    /// 查询某模块的有效级别：有覆盖用覆盖，否则回退全局。
    #[must_use]
    pub fn effective_level(&self, module: &str) -> LogLevel {
        self.config
            .module_overrides
            .get(module)
            .copied()
            .unwrap_or(self.config.global)
    }

    /// 更新全局级别。
    pub fn set_global(&mut self, level: LogLevel) {
        self.config.global = level;
    }

    /// 设置某模块的覆盖级别。
    pub fn set_module_level(&mut self, module: &str, level: LogLevel) {
        self.config
            .module_overrides
            .insert(module.to_string(), level);
    }

    /// 判断某模块在给定级别上是否应输出：
    /// 该级别 severity <= 有效级别 severity 才输出（更重要或同级才打印）。
    #[must_use]
    pub fn enabled(&self, module: &str, level: LogLevel) -> bool {
        level.severity() <= self.effective_level(module).severity()
    }

    /// 提议应用新配置（纯逻辑热加载门控）。
    ///
    /// 本骨架简化为总是 `Applied` 并把当前配置整体替换为 `new_config`；
    /// 真实校验（级别合法性、模块白名单）留 TODO。
    pub fn propose(&mut self, new_config: LogLevelConfig) -> LevelApplyResult {
        let global = new_config.global;
        self.config = new_config;
        LevelApplyResult::Applied { global }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_parses_each_level_case_insensitive() {
        assert_eq!("ERROR".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("Warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("DEBUG".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
    }

    #[test]
    fn from_str_rejects_invalid() {
        let err = "verbose".parse::<LogLevel>().unwrap_err();
        assert!(matches!(err, LogLevelError::InvalidLevel { .. }));
        assert!(err.to_string().contains("LOG_LEVEL_INVALID"));
    }

    #[test]
    fn as_str_roundtrip() {
        for lvl in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            let s = lvl.as_str();
            assert_eq!(s.parse::<LogLevel>().unwrap(), lvl);
        }
    }

    #[test]
    fn severity_ordering() {
        assert_eq!(LogLevel::Error.severity(), 0);
        assert_eq!(LogLevel::Trace.severity(), 4);
        assert!(LogLevel::Error.severity() < LogLevel::Info.severity());
        assert!(LogLevel::Debug.severity() < LogLevel::Trace.severity());
    }

    #[test]
    fn override_takes_effect_and_global_falls_back() {
        let mut cfg = LogLevelConfig::new(LogLevel::Info);
        cfg.set_module("connectivity".to_string(), LogLevel::Debug);
        let ctl = LogLevelController::new(cfg);
        assert_eq!(ctl.effective_level("connectivity"), LogLevel::Debug);
        // 未覆盖模块回退全局。
        assert_eq!(ctl.effective_level("routing"), LogLevel::Info);
    }

    #[test]
    fn enabled_threshold_uses_severity() {
        let cfg = LogLevelConfig::new(LogLevel::Info);
        let ctl = LogLevelController::new(cfg);
        // info 全局：debug/trace 不输出，error/warn/info 输出。
        assert!(!ctl.enabled("routing", LogLevel::Debug));
        assert!(!ctl.enabled("routing", LogLevel::Trace));
        assert!(ctl.enabled("routing", LogLevel::Error));
        assert!(ctl.enabled("routing", LogLevel::Warn));
        assert!(ctl.enabled("routing", LogLevel::Info));
    }

    #[test]
    fn set_global_changes_effective_for_unoverridden() {
        let cfg = LogLevelConfig::new(LogLevel::Info);
        let mut ctl = LogLevelController::new(cfg);
        assert_eq!(ctl.effective_level("routing"), LogLevel::Info);
        ctl.set_global(LogLevel::Warn);
        assert_eq!(ctl.effective_level("routing"), LogLevel::Warn);
        // 全局降到 Warn 后，info 不再输出。
        assert!(!ctl.enabled("routing", LogLevel::Info));
        assert!(ctl.enabled("routing", LogLevel::Warn));
    }

    #[test]
    fn set_module_level_updates_override() {
        let cfg = LogLevelConfig::new(LogLevel::Info);
        let mut ctl = LogLevelController::new(cfg);
        assert_eq!(ctl.effective_level("routing"), LogLevel::Info);
        ctl.set_module_level("routing", LogLevel::Trace);
        assert_eq!(ctl.effective_level("routing"), LogLevel::Trace);
        assert!(ctl.enabled("routing", LogLevel::Trace));
    }

    #[test]
    fn propose_applies_new_config() {
        let cfg = LogLevelConfig::new(LogLevel::Info);
        let mut ctl = LogLevelController::new(cfg);
        let mut new_cfg = LogLevelConfig::new(LogLevel::Warn);
        new_cfg.set_module("routing".to_string(), LogLevel::Error);
        let r = ctl.propose(new_cfg);
        assert_eq!(r.as_str(), "applied");
        assert!(matches!(
            r,
            LevelApplyResult::Applied {
                global: LogLevel::Warn
            }
        ));
        // 新全局与新覆盖都生效。
        assert_eq!(ctl.effective_level("anything"), LogLevel::Warn);
        assert_eq!(ctl.effective_level("routing"), LogLevel::Error);
    }

    #[test]
    fn level_display_matches_as_str() {
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }
}
