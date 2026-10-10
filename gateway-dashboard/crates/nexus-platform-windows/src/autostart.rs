//! # 当前用户 ONLOGON 计划任务自启（PRODUCT §13）
//!
//! 经 `schtasks.exe` 注册/移除/查询“当前用户登录时启动 nexusd”的计划任务。
//! 选择计划任务而非 Windows 服务：WinINET 系统代理是 HKCU 交互用户状态，
//! SYSTEM 服务操作的是 `HKU\.DEFAULT`，无法接管当前桌面用户的代理。
//!
//! - 本模块为安全 Rust（不直接 FFI）；经 `std::process::Command` 调用 schtasks。
//! - 命令构造为纯函数，单元测试覆盖任务名前缀与参数拼装，不真正改动系统。
//! - 临时测试任务名必须带 `nexus-test-` 前缀（由调用方传入）。

use nexus_platform::{AutostartRegistrar, PlatformError};
use std::process::Command;

/// 正式自启任务名。
pub const AUTOSTART_TASK_NAME: &str = "nexus-autostart";

fn map_io(op: &str, e: std::io::Error) -> PlatformError {
    PlatformError::Io {
        operation: op.to_string(),
        message: e.to_string(),
    }
}

/// 构造 `schtasks /Create` 参数向量（纯函数，可单测）。
///
/// `/TR` 把 exe 路径与参数拼成一个带引号的命令行；`/SC ONLOGON` 当前用户登录触发；
/// `/F` 覆盖已存在同名任务（幂等 install）。
pub(crate) fn build_create_args(task_name: &str, exe: &str, args: &[&str]) -> Vec<String> {
    let mut tr = format!("\"{exe}\"");
    for a in args {
        tr.push(' ');
        tr.push_str(a);
    }
    vec![
        "/Create".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/TR".to_string(),
        tr,
        "/SC".to_string(),
        "ONLOGON".to_string(),
        "/F".to_string(),
    ]
}

/// 构造 `schtasks /Delete` 参数向量（纯函数，可单测）。
pub(crate) fn build_delete_args(task_name: &str) -> Vec<String> {
    vec![
        "/Delete".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/F".to_string(),
    ]
}

/// 构造 `schtasks /Query` 参数向量（纯函数，可单测）。
pub(crate) fn build_query_args(task_name: &str) -> Vec<String> {
    vec![
        "/Query".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
    ]
}

/// `schtasks.exe` 计划任务自启注册器。
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskSchedulerAutostart {
    task_name: &'static str,
}

impl TaskSchedulerAutostart {
    /// 以正式任务名 `nexus-autostart` 创建注册器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_name: AUTOSTART_TASK_NAME,
        }
    }

    /// 以自定义任务名创建（测试用，调用方负责带 `nexus-test-` 前缀并清理）。
    #[must_use]
    pub fn with_task_name(task_name: &'static str) -> Self {
        Self { task_name }
    }

    fn spawn(args: &[String]) -> Result<bool, PlatformError> {
        let out = Command::new("schtasks.exe")
            .args(args)
            .output()
            .map_err(|e| map_io("schtasks", e))?;
        Ok(out.status.success())
    }
}

impl AutostartRegistrar for TaskSchedulerAutostart {
    fn install(&self, exe_path: &str, args: &[&str]) -> Result<String, PlatformError> {
        let argv = build_create_args(self.task_name, exe_path, args);
        let ok = Self::spawn(&argv)?;
        if !ok {
            return Err(PlatformError::Io {
                operation: "schtasks /Create".to_string(),
                message: format!("create task {} failed", self.task_name),
            });
        }
        Ok(self.task_name.to_string())
    }

    fn remove(&self) -> Result<(), PlatformError> {
        let argv = build_delete_args(self.task_name);
        // 删除不存在的任务 schtasks 返回非 0；按契约视为成功（幂等）。
        let _ = Self::spawn(&argv)?;
        Ok(())
    }

    fn is_installed(&self) -> Result<bool, PlatformError> {
        let argv = build_query_args(self.task_name);
        Self::spawn(&argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_args_wraps_exe_and_appends_args() {
        let argv = build_create_args(
            "nexus-test-x",
            r"D:\nexusd.exe",
            &["serve", "--addr", "127.0.0.1:7898"],
        );
        assert_eq!(argv[0], "/Create");
        assert_eq!(argv[1], "/TN");
        assert_eq!(argv[2], "nexus-test-x");
        assert_eq!(argv[3], "/TR");
        assert_eq!(argv[4], "\"D:\\nexusd.exe\" serve --addr 127.0.0.1:7898");
        assert_eq!(argv[5], "/SC");
        assert_eq!(argv[6], "ONLOGON");
        assert_eq!(argv[7], "/F");
    }

    #[test]
    fn delete_args_are_idempotent() {
        let argv = build_delete_args("nexus-test-x");
        assert_eq!(argv, vec!["/Delete", "/TN", "nexus-test-x", "/F"]);
    }

    #[test]
    fn query_args_target_task() {
        let argv = build_query_args("nexus-autostart");
        assert_eq!(argv, vec!["/Query", "/TN", "nexus-autostart"]);
    }

    #[test]
    fn default_task_name_is_nexus_autostart() {
        assert_eq!(TaskSchedulerAutostart::new().task_name, "nexus-autostart");
    }
}
