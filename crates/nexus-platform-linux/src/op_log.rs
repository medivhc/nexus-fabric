//! OS 装配操作日志（O6 可观测）。
//!
//! - 结构化行日志（JSON lines），追加写入 `os_assemble.log`（路径可配置）；
//! - 写文件失败（无权限等）→ 降级输出到 stderr，操作本身不失败、不 panic；
//! - 日志是可观测性，不影响幂等语义与事务正确性。

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 默认日志文件名（O6 契约字面要求）。
pub const DEFAULT_LOG_FILE: &str = "os_assemble.log";

/// 操作日志写者：持路径，`log()` 追加一行 JSON。
#[derive(Debug, Clone)]
pub struct OpLog {
    path: PathBuf,
}

impl OpLog {
    /// 创建。`path=None` → 当前目录 `os_assemble.log`。
    pub fn new(path: Option<PathBuf>) -> Self {
        OpLog {
            path: path.unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_FILE)),
        }
    }

    /// 日志路径（只读）。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 记录一条操作事件。`fields` 为有序键值对（已按调用顺序输出）。
    ///
    /// 写文件失败时降级到 stderr；永不 panic，永不影响调用方操作结果。
    pub fn log(&self, op: &str, fields: &[(&str, &str)]) {
        let mut line = String::with_capacity(128);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = write!(line, "{{\"ts\":{ts},\"op\":\"{op}\"");
        for (k, v) in fields {
            let _ = write!(line, ",\"{k}\":\"{v}\"");
        }
        line.push('}');

        let write_file = || -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{line}")?;
            Ok(())
        };
        if let Err(e) = write_file() {
            // 降级：stderr。不抛错、不 panic。
            eprintln!(
                "[os_assemble.log fallback] {line} (write {}: {e})",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn log_appends_json_line() {
        let dir = std::env::temp_dir().join(format!("oplog-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test.log");
        let log = OpLog::new(Some(path.clone()));
        log.log("apply", &[("ifname", "nxstest0"), ("result", "ok")]);
        let content = fs::read_to_string(&path).expect("log file");
        assert!(content.contains("\"op\":\"apply\""));
        assert!(content.contains("\"ifname\":\"nxstest0\""));
        assert!(content.contains("\"result\":\"ok\""));
        assert!(content.contains("\"ts\":"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_to_bad_path_falls_back_to_stderr_without_panic() {
        // 不可写路径 → 不 panic（降级 stderr）。
        let log = OpLog::new(Some(PathBuf::from("/nonexistent-dir-xyz/oplog.log")));
        log.log("apply", &[("result", "ok")]);
        // 能执行到这里即通过。
    }

    #[test]
    fn default_path_is_contract_name() {
        let log = OpLog::new(None);
        assert_eq!(log.path().as_os_str(), DEFAULT_LOG_FILE);
    }
}
