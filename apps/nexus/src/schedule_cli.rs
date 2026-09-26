//! PRODUCT §14 计划任务 CLI 组合根（apps/nexus）：
//! `nexus schedule at|every|list|cancel|tick` 的进程内实现 + 注册表持久化。
//!
//! crate（`nexus-scheduler`）保持零 I/O；组合根负责 `SchedulerSnapshot` 落盘/重载
//! （PRODUCT §14.2 / §14.4，状态权威来源为本地快照文件，恢复为幂等操作）。
//! 触发动作（`SubmitFn`）只生成 task id，不实现执行路径（P0 冻结边界）。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_scheduler::{ScheduleError, ScheduleSpec, Scheduler, TaskIntent};
use serde_json::{Value, json};

/// 默认注册表路径：`$NEXUS_HOME/schedule.json` 或 `~/.nexus/schedule.json`。
pub fn default_state_path() -> PathBuf {
    if let Ok(home) = std::env::var("NEXUS_HOME") {
        let dir = PathBuf::from(home);
        if dir.exists() {
            return dir.join("schedule.json");
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        return PathBuf::from(home).join(".nexus").join("schedule.json");
    }
    PathBuf::from(".nexus").join("schedule.json")
}

/// 当前 Unix 秒（墙钟；CLI tick 与注册校验共用）。
pub fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 组合根错误：PRODUCT §14.3 三种业务错误之外的注册表基础设施错误（I/O / 损坏）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleCliError {
    /// 业务错误（INVALID_SCHEDULE / SCHEDULE_NOT_FOUND / SUBMIT_FAILED）。
    Schedule(ScheduleError),
    /// 状态文件读/写/解析失败。不静默丢弃损坏快照（PRODUCT §14.4 精神）。
    State(String),
}

impl std::fmt::Display for ScheduleCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScheduleCliError::Schedule(e) => write!(f, "{e}"),
            ScheduleCliError::State(m) => write!(f, "schedule state error: {m}"),
        }
    }
}

impl std::error::Error for ScheduleCliError {}

impl From<ScheduleError> for ScheduleCliError {
    fn from(e: ScheduleError) -> Self {
        ScheduleCliError::Schedule(e)
    }
}

/// 从状态文件载入调度器：文件不存在 → 空调度器；损坏 → Err（不静默丢弃）。
fn load_scheduler(state_path: &Path) -> Result<Scheduler, ScheduleCliError> {
    let Ok(bytes) = std::fs::read(state_path) else {
        return Ok(Scheduler::new());
    };
    let snap: nexus_scheduler::SchedulerSnapshot = serde_json::from_slice(&bytes).map_err(|e| {
        ScheduleCliError::State(format!(
            "corrupt schedule state at {}: {e}",
            state_path.display()
        ))
    })?;
    Ok(Scheduler::restore(snap))
}

/// 持久化当前注册表快照（PRODUCT §14.2）。先建父目录，再写同目录临时文件并
/// rename 原子替换（AGENTS §15 Crash Consistency：进程中途崩溃不留下截断快照）。
fn save_scheduler(state_path: &Path, s: &Scheduler) -> Result<(), ScheduleCliError> {
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ScheduleCliError::State(format!(
                "cannot create schedule state dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    let text = serde_json::to_string_pretty(&s.snapshot())
        .map_err(|e| ScheduleCliError::State(format!("cannot serialize schedule state: {e}")))?;
    let tmp = state_path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| {
        ScheduleCliError::State(format!(
            "cannot write schedule state {}: {e}",
            tmp.display()
        ))
    })?;
    std::fs::rename(&tmp, state_path).map_err(|e| {
        ScheduleCliError::State(format!(
            "cannot commit schedule state {}: {e}",
            state_path.display()
        ))
    })
}

/// 触发回调（组合根最小实现，PRODUCT §14.2）：生成 task id，不做执行路径。
fn make_submit() -> nexus_scheduler::SubmitFn<'static> {
    Box::new(|intent: &TaskIntent| Ok(format!("task-{}", intent.resource)))
}

/// 构造意图并校验非空（PRODUCT §14.3 `INVALID_SCHEDULE`）。
fn make_intent(resource: &str, command: &[String]) -> Result<TaskIntent, ScheduleError> {
    TaskIntent::new(resource.to_string(), command.to_vec(), None).ok_or_else(|| {
        ScheduleError::InvalidSchedule("resource and command must be non-empty".to_string())
    })
}

/// `schedule at <ts>`：一次性注册（PRODUCT §14.1）。过去时间 → `INVALID_SCHEDULE`。
pub fn schedule_at(
    timestamp_secs: i64,
    resource: &str,
    command: &[String],
    state_path: &Path,
) -> Result<Value, ScheduleCliError> {
    let mut s = load_scheduler(state_path)?;
    let intent = make_intent(resource, command)?;
    let id = s.register(ScheduleSpec::At { timestamp_secs }, intent, unix_now_secs())?;
    save_scheduler(state_path, &s)?;
    let entry = s
        .get(&id)
        .ok_or_else(|| ScheduleCliError::Schedule(ScheduleError::ScheduleNotFound(id.clone())))?;
    Ok(json!({
        "verdict": "PASS",
        "command": "schedule at",
        "schedule_id": id,
        "next_run_secs": entry.next_run_secs,
        "spec": entry.spec,
        "resource": entry.intent.resource,
        "command": entry.intent.command,
    }))
}

/// `schedule every <secs>`：周期注册（PRODUCT §14.1）。`secs <= 0` → `INVALID_SCHEDULE`。
pub fn schedule_every(
    interval_secs: i64,
    resource: &str,
    command: &[String],
    state_path: &Path,
) -> Result<Value, ScheduleCliError> {
    let mut s = load_scheduler(state_path)?;
    let intent = make_intent(resource, command)?;
    let id = s.register(
        ScheduleSpec::Every { interval_secs },
        intent,
        unix_now_secs(),
    )?;
    save_scheduler(state_path, &s)?;
    let entry = s
        .get(&id)
        .ok_or_else(|| ScheduleCliError::Schedule(ScheduleError::ScheduleNotFound(id.clone())))?;
    Ok(json!({
        "verdict": "PASS",
        "command": "schedule every",
        "schedule_id": id,
        "next_run_secs": entry.next_run_secs,
        "spec": entry.spec,
        "resource": entry.intent.resource,
        "command": entry.intent.command,
    }))
}

/// `schedule list`：列出全部条目（空表输出空数组，PRODUCT §14.1）。
pub fn schedule_list(state_path: &Path) -> Result<Value, ScheduleCliError> {
    let s = load_scheduler(state_path)?;
    let entries = s.list();
    Ok(json!({
        "verdict": "PASS",
        "command": "schedule list",
        "count": entries.len(),
        "schedules": entries,
    }))
}

/// `schedule cancel <id>`：取消 `Scheduled` 条目（PRODUCT §14.1 / §14.3）。
/// `Fired` / 已取消 / 不存在 → `SCHEDULE_NOT_FOUND`。
pub fn schedule_cancel(id: &str, state_path: &Path) -> Result<Value, ScheduleCliError> {
    let mut s = load_scheduler(state_path)?;
    s.cancel(id)?;
    save_scheduler(state_path, &s)?;
    Ok(json!({
        "verdict": "PASS",
        "command": "schedule cancel",
        "schedule_id": id,
        "state": "Cancelled",
    }))
}

/// `schedule tick`：推进调度，触发全部到期条目并提交执行意图（PRODUCT §14.1 / §14.2）。
/// `now_secs` 由调用方注入（CLI 用墙钟）；每次触发至多提交一次，失败语义见 §14.3。
pub fn schedule_tick(state_path: &Path, now_secs: i64) -> Result<Value, ScheduleCliError> {
    let mut s = load_scheduler(state_path)?;
    let mut submit = make_submit();
    let records = s.tick(now_secs, &mut submit);
    save_scheduler(state_path, &s)?;
    Ok(json!({
        "verdict": "PASS",
        "command": "schedule tick",
        "now_secs": now_secs,
        "fired": records.len(),
        "records": records,
    }))
}

/// 错误 → 结构化 verdict JSON（PRODUCT §14.3 错误名；基础设施错误用 `STATE_ERROR`）。
pub fn error_json(command: &str, err: &ScheduleCliError) -> Value {
    match err {
        ScheduleCliError::Schedule(ScheduleError::InvalidSchedule(m)) => json!({
            "verdict": "INVALID_SCHEDULE", "command": command, "error": m,
        }),
        ScheduleCliError::Schedule(ScheduleError::ScheduleNotFound(m)) => json!({
            "verdict": "SCHEDULE_NOT_FOUND", "command": command, "error": m,
        }),
        ScheduleCliError::Schedule(ScheduleError::SubmitFailed(m)) => json!({
            "verdict": "SUBMIT_FAILED", "command": command, "error": m,
        }),
        ScheduleCliError::State(m) => json!({
            "verdict": "FAIL",
            "command": command,
            "error": { "code": "STATE_ERROR", "message": m },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nexus-schedule-cli-unit-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("schedule.json");
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn at_registers_and_persists() {
        let state = tmp_state("at");
        let now = unix_now_secs();
        let v = schedule_at(
            now + 1000,
            "rust-build",
            &["cargo".into(), "test".into()],
            &state,
        )
        .unwrap();
        assert_eq!(v["verdict"], "PASS");
        assert!(v["schedule_id"].as_str().unwrap().starts_with("sch-"));
        // 持久化：重新载入仍有条目
        let l = schedule_list(&state).unwrap();
        assert_eq!(l["count"], 1);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn at_past_rejected() {
        let state = tmp_state("at-past");
        let now = unix_now_secs();
        let err = schedule_at(now - 1, "r", &["echo".into()], &state).unwrap_err();
        assert!(matches!(
            err,
            ScheduleCliError::Schedule(ScheduleError::InvalidSchedule(_))
        ));
        let j = error_json("schedule at", &err);
        assert_eq!(j["verdict"], "INVALID_SCHEDULE");
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn every_rejects_nonpositive() {
        let state = tmp_state("every");
        let err = schedule_every(0, "r", &["echo".into()], &state).unwrap_err();
        assert!(matches!(
            err,
            ScheduleCliError::Schedule(ScheduleError::InvalidSchedule(_))
        ));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn empty_command_rejected() {
        let state = tmp_state("empty");
        let now = unix_now_secs();
        let err = schedule_at(now + 1000, "r", &[], &state).unwrap_err();
        assert!(matches!(
            err,
            ScheduleCliError::Schedule(ScheduleError::InvalidSchedule(_))
        ));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn cancel_and_not_found() {
        let state = tmp_state("cancel");
        let now = unix_now_secs();
        let v = schedule_at(now + 1000, "r", &["echo".into()], &state).unwrap();
        let id = v["schedule_id"].as_str().unwrap().to_string();
        let c = schedule_cancel(&id, &state).unwrap();
        assert_eq!(c["state"], "Cancelled");
        // 已取消再 cancel → SCHEDULE_NOT_FOUND
        let err = schedule_cancel(&id, &state).unwrap_err();
        assert!(matches!(
            err,
            ScheduleCliError::Schedule(ScheduleError::ScheduleNotFound(_))
        ));
        let j = error_json("schedule cancel", &err);
        assert_eq!(j["verdict"], "SCHEDULE_NOT_FOUND");
        // 不存在的 id
        assert!(schedule_cancel("sch-999", &state).is_err());
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn tick_fires_due_only_and_persists() {
        let state = tmp_state("tick");
        let now = unix_now_secs();
        // 过去时间的 at 注册被拒绝（INVALID_SCHEDULE，见 at_past_rejected）。
        assert!(schedule_at(now - 1, "due", &["echo".into()], &state).is_err());
        let v = schedule_at(now + 10, "soon", &["echo".into()], &state).unwrap();
        let id = v["schedule_id"].as_str().unwrap().to_string();
        let t = schedule_tick(&state, now + 11).unwrap(); // 到期
        assert_eq!(t["fired"], 1);
        assert_eq!(t["records"][0]["schedule_id"], id);
        assert_eq!(t["records"][0]["ok"], true);
        let l = schedule_list(&state).unwrap();
        assert_eq!(l["schedules"][0]["state"], "fired");
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn corrupt_state_is_error_not_silent_reset() {
        let state = tmp_state("corrupt");
        std::fs::write(&state, b"not json").unwrap();
        let err = schedule_list(&state).unwrap_err();
        assert!(matches!(err, ScheduleCliError::State(_)));
        let j = error_json("schedule list", &err);
        assert_eq!(j["error"]["code"], "STATE_ERROR");
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn error_json_submit_failed_renders() {
        // PRODUCT §14.3 `SUBMIT_FAILED`：组合根渲染分支（回调失败时 TriggerRecord 保留错误）。
        let err = ScheduleCliError::Schedule(ScheduleError::SubmitFailed("submit boom".into()));
        let j = error_json("schedule tick", &err);
        assert_eq!(j["verdict"], "SUBMIT_FAILED");
        assert_eq!(j["error"], "submit boom");
    }
}
