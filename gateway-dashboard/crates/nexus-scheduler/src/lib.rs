//! 计划任务调度器（PRODUCT §14）——portable-core，零 Nexus 内部依赖。
//!
//! 职责：时间表（`At` 一次性 / `Every` 周期）注册、取消、列表与到期触发判定
//! （`tick`）。触发动作不在此 crate 内执行——由组合根注入的 `SubmitFn` 回调
//! 完成；本 crate 只负责「何时触发、触发一次、触发后如何推进」。
//!
//! 持久化：组合根通过 `SchedulerSnapshot` 完成注册表序列化与恢复
//! （PRODUCT §14.2 / §14.4）。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 调度时间表（P0 冻结：`At` 一次性 / `Every` 周期）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScheduleSpec {
    /// 一次性：到达 `timestamp_secs`（Unix 秒）触发一次。
    At { timestamp_secs: i64 },
    /// 周期：注册后每 `interval_secs` 触发一次，`next_run` 逐次前移。
    Every { interval_secs: i64 },
}

impl ScheduleSpec {
    /// 计算首次运行时间；非法输入返回 None（由 register 转为错误）。
    fn first_run(&self, now_secs: i64) -> Option<i64> {
        match *self {
            ScheduleSpec::At { timestamp_secs } => {
                if timestamp_secs <= now_secs {
                    None
                } else {
                    Some(timestamp_secs)
                }
            }
            ScheduleSpec::Every { interval_secs } => {
                if interval_secs <= 0 {
                    None
                } else {
                    Some(now_secs + interval_secs)
                }
            }
        }
    }
}

/// 条目生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleState {
    /// 等待到期触发。
    Scheduled,
    /// `At` 条目已触发，不再运行。
    Fired,
    /// 已被用户取消，不再运行。
    Cancelled,
}

/// 触发时提交的执行意图快照；组合根据此构造结构化 Intent（PRODUCT §6 / §10.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskIntent {
    pub resource: String,
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

impl TaskIntent {
    /// 构造；空 resource / 空 command 返回 None（由 register 转为 `InvalidSchedule`）。
    pub fn new(resource: String, command: Vec<String>, project: Option<String>) -> Option<Self> {
        if resource.is_empty() || command.is_empty() {
            return None;
        }
        Some(Self {
            resource,
            command,
            project,
        })
    }
}

/// 一条计划任务。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub id: String,
    pub spec: ScheduleSpec,
    pub intent: TaskIntent,
    /// 下一次到期时间（Unix 秒）。
    pub next_run_secs: i64,
    pub state: ScheduleState,
    /// 已成功触发次数。
    pub fire_count: u64,
}

/// 一次 tick 中的触发结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerRecord {
    pub schedule_id: String,
    pub trigger_at_secs: i64,
    /// 提交是否成功；失败时 `task_id` 为 None 且条目保持 `Scheduled`。
    pub ok: bool,
    pub task_id: Option<String>,
    /// 触发成功后的累计触发次数（失败时为触发前的值）。
    pub fire_count: u64,
    /// 提交失败时的错误消息（PRODUCT §14.3 SUBMIT_FAILED，供 Retry / Escalate 判断）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 调度器序列化快照（组合根持久化 / 恢复用，PRODUCT §14.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerSnapshot {
    pub entries: Vec<ScheduleEntry>,
    pub next_id: u64,
}

/// 调度错误（PRODUCT §14.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// `At` 为过去时间 / `interval_secs` ≤ 0 / 缺 resource 或 command。
    InvalidSchedule(String),
    /// cancel 不存在的 id，或条目已 `Fired` / 已 `Cancelled`。
    ScheduleNotFound(String),
    /// 触发时 Intent 提交失败。
    SubmitFailed(String),
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScheduleError::InvalidSchedule(m) => write!(f, "invalid schedule: {m}"),
            ScheduleError::ScheduleNotFound(m) => write!(f, "schedule not found: {m}"),
            ScheduleError::SubmitFailed(m) => write!(f, "submit failed: {m}"),
        }
    }
}

impl std::error::Error for ScheduleError {}

/// 触发回调：提交结构化执行意图，返回 task id。
pub type SubmitFn<'a> = Box<dyn FnMut(&TaskIntent) -> Result<String, ScheduleError> + 'a>;

/// 内存调度器。
#[derive(Debug)]
pub struct Scheduler {
    entries: BTreeMap<String, ScheduleEntry>,
    next_id: u64,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            entries: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// 注册计划任务；返回 schedule id。
    ///
    /// `now_secs` 用于校验 `At` 必须为未来时间（PRODUCT §14.3 `INVALID_SCHEDULE`）。
    pub fn register(
        &mut self,
        spec: ScheduleSpec,
        intent: TaskIntent,
        now_secs: i64,
    ) -> Result<String, ScheduleError> {
        let next_run = spec.first_run(now_secs).ok_or_else(|| {
            ScheduleError::InvalidSchedule(match &spec {
                ScheduleSpec::At { timestamp_secs } => {
                    format!("at must be in the future (at={timestamp_secs}, now={now_secs})")
                }
                ScheduleSpec::Every { interval_secs } => {
                    format!("interval_secs must be positive (got {interval_secs})")
                }
            })
        })?;
        if intent.resource.is_empty() || intent.command.is_empty() {
            return Err(ScheduleError::InvalidSchedule(
                "resource and command must be non-empty".to_string(),
            ));
        }
        let id = format!("sch-{}", self.next_id);
        self.next_id += 1;
        self.entries.insert(
            id.clone(),
            ScheduleEntry {
                id: id.clone(),
                spec,
                intent,
                next_run_secs: next_run,
                state: ScheduleState::Scheduled,
                fire_count: 0,
            },
        );
        Ok(id)
    }

    /// 取消计划任务；仅允许 `Scheduled` 条目（PRODUCT §14.3 `SCHEDULE_NOT_FOUND`）。
    pub fn cancel(&mut self, id: &str) -> Result<(), ScheduleError> {
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| ScheduleError::ScheduleNotFound(format!("schedule {id} not found")))?;
        match entry.state {
            ScheduleState::Scheduled => {
                entry.state = ScheduleState::Cancelled;
                Ok(())
            }
            _ => Err(ScheduleError::ScheduleNotFound(format!(
                "schedule {id} is not cancellable (state={:?})",
                entry.state
            ))),
        }
    }

    /// 返回全部计划任务（按 id 排序）。
    pub fn list(&self) -> Vec<ScheduleEntry> {
        self.entries.values().cloned().collect()
    }

    /// 按 id 查询。
    pub fn get(&self, id: &str) -> Option<&ScheduleEntry> {
        self.entries.get(id)
    }

    /// 推进调度器：触发所有 `Scheduled` 且 `next_run_secs <= now_secs` 的条目。
    ///
    /// 幂等与推进语义（PRODUCT §14.4）：
    /// - 同一 tick 内每个条目至多触发一次；
    /// - `At` 触发成功后置 `Fired`，永不再触发；
    /// - `Every` 触发成功后 `next_run_secs += interval_secs` 并保持 `Scheduled`；
    /// - 提交失败时条目保持 `Scheduled`（`next_run_secs` 不变），下次 tick 重试，
    ///   结果以 `TriggerRecord { ok: false }` 呈现。
    pub fn tick<'a>(&mut self, now_secs: i64, submit: &mut SubmitFn<'a>) -> Vec<TriggerRecord> {
        let due: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.state == ScheduleState::Scheduled && e.next_run_secs <= now_secs)
            .map(|(id, _)| id.clone())
            .collect();

        let mut records = Vec::with_capacity(due.len());
        for id in due {
            let entry = match self.entries.get_mut(&id) {
                Some(e) => e,
                None => continue,
            };
            if entry.state != ScheduleState::Scheduled || entry.next_run_secs > now_secs {
                continue; // 保护：本 tick 内已推进过
            }
            let intent = entry.intent.clone();
            let trigger_at = entry.next_run_secs;
            match submit(&intent) {
                Ok(task_id) => {
                    entry.fire_count += 1;
                    let fire_count = entry.fire_count;
                    match &entry.spec {
                        ScheduleSpec::At { .. } => {
                            entry.state = ScheduleState::Fired;
                        }
                        ScheduleSpec::Every { interval_secs } => {
                            entry.next_run_secs += interval_secs;
                        }
                    }
                    records.push(TriggerRecord {
                        schedule_id: id,
                        trigger_at_secs: trigger_at,
                        ok: true,
                        task_id: Some(task_id),
                        fire_count,
                        error: None,
                    });
                }
                Err(e) => {
                    records.push(TriggerRecord {
                        schedule_id: id,
                        trigger_at_secs: trigger_at,
                        ok: false,
                        task_id: None,
                        fire_count: entry.fire_count,
                        error: Some(format!("{e}")),
                    });
                    // 条目保持不变：下次 tick 重试（PRODUCT §14.3 SUBMIT_FAILED）。
                }
            }
        }
        records
    }

    /// 序列化快照（组合根持久化用）。
    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            entries: self.list(),
            next_id: self.next_id,
        }
    }

    /// 从快照恢复（崩溃 / 重启后重建，PRODUCT §14.4）。
    pub fn restore(snapshot: SchedulerSnapshot) -> Self {
        Scheduler {
            entries: snapshot
                .entries
                .into_iter()
                .map(|e| (e.id.clone(), e))
                .collect(),
            next_id: snapshot.next_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 计数提交回调：返回回调与共享调用记录（Rc 共享，避免借用冲突）。
    fn counting_submit() -> (SubmitFn<'static>, Rc<RefCell<Vec<TaskIntent>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let inner = calls.clone();
        let mut seq = 0usize;
        let f: SubmitFn<'static> = Box::new(move |intent: &TaskIntent| {
            inner.borrow_mut().push(intent.clone());
            seq += 1;
            Ok(format!("task-{seq}"))
        });
        (f, calls)
    }

    #[test]
    fn register_rejects_invalid() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap();

        // at 为过去时间
        assert!(matches!(
            s.register(
                ScheduleSpec::At {
                    timestamp_secs: 100
                },
                intent.clone(),
                200
            ),
            Err(ScheduleError::InvalidSchedule(_))
        ));
        // interval <= 0
        assert!(matches!(
            s.register(
                ScheduleSpec::Every { interval_secs: 0 },
                intent.clone(),
                100
            ),
            Err(ScheduleError::InvalidSchedule(_))
        ));
        // 空命令 / 空 resource 在意图构造层被拒绝（TaskIntent::new 返回 None）
        assert!(TaskIntent::new("rust-build".into(), vec![], None).is_none());
        assert!(TaskIntent::new(String::new(), vec!["cargo".into()], None).is_none());
    }

    #[test]
    fn at_fires_once_and_only_once() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new(
            "rust-build".into(),
            vec!["cargo".into(), "test".into()],
            None,
        )
        .unwrap();
        let id = s
            .register(
                ScheduleSpec::At {
                    timestamp_secs: 100,
                },
                intent,
                0,
            )
            .unwrap();
        let (mut submit, calls) = counting_submit();

        // 未到期：不触发
        assert!(s.tick(99, &mut submit).is_empty());
        assert!(calls.borrow().is_empty());

        // 到期：触发一次
        let recs = s.tick(100, &mut submit);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].ok);
        assert_eq!(recs[0].schedule_id, id);
        assert_eq!(recs[0].task_id.as_deref(), Some("task-1"));
        assert_eq!(recs[0].fire_count, 1);
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(s.get(&id).unwrap().state, ScheduleState::Fired);

        // 后续 tick 不重复提交
        assert!(s.tick(200, &mut submit).is_empty());
        assert_eq!(calls.borrow().len(), 1);
        // Fired 条目不可取消
        assert!(matches!(
            s.cancel(&id),
            Err(ScheduleError::ScheduleNotFound(_))
        ));
    }

    #[test]
    fn every_reschedules_and_keeps_firing() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap();
        let id = s
            .register(ScheduleSpec::Every { interval_secs: 50 }, intent, 0)
            .unwrap();
        let (mut submit, calls) = counting_submit();

        // t=50 到期触发，next_run 前移到 100
        let recs = s.tick(50, &mut submit);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].ok);
        assert_eq!(s.get(&id).unwrap().next_run_secs, 100);
        assert_eq!(s.get(&id).unwrap().state, ScheduleState::Scheduled);
        assert_eq!(s.get(&id).unwrap().fire_count, 1);

        // t=100 再次触发
        let recs2 = s.tick(100, &mut submit);
        assert_eq!(recs2.len(), 1);
        assert_eq!(recs2[0].fire_count, 2);
        assert_eq!(s.get(&id).unwrap().next_run_secs, 150);
        assert_eq!(calls.borrow().len(), 2);
    }

    #[test]
    fn submit_failure_keeps_entry_for_retry() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap();
        let id = s
            .register(
                ScheduleSpec::At {
                    timestamp_secs: 100,
                },
                intent,
                0,
            )
            .unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_inner = calls.clone();
        let mut fail_once = true;
        let mut submit: SubmitFn<'static> = Box::new(move |intent: &TaskIntent| {
            calls_inner.borrow_mut().push(intent.clone());
            if fail_once {
                fail_once = false;
                Err(ScheduleError::SubmitFailed("busy".to_string()))
            } else {
                Ok("task-ok".to_string())
            }
        });

        // 第一次触发失败：ok=false，条目保持 Scheduled
        let recs = s.tick(100, &mut submit);
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].ok);
        assert_eq!(recs[0].task_id, None);
        assert_eq!(s.get(&id).unwrap().state, ScheduleState::Scheduled);
        assert_eq!(s.get(&id).unwrap().fire_count, 0);

        // 下次 tick 重试成功
        let recs2 = s.tick(100, &mut submit);
        assert_eq!(recs2.len(), 1);
        assert!(recs2[0].ok);
        assert_eq!(s.get(&id).unwrap().state, ScheduleState::Fired);
        assert_eq!(calls.borrow().len(), 2);
    }

    #[test]
    fn cancel_prevents_fire() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap();
        let id = s
            .register(
                ScheduleSpec::At {
                    timestamp_secs: 100,
                },
                intent,
                0,
            )
            .unwrap();
        let (mut submit, calls) = counting_submit();

        s.cancel(&id).unwrap();
        assert_eq!(s.get(&id).unwrap().state, ScheduleState::Cancelled);
        assert!(s.tick(200, &mut submit).is_empty());
        assert!(calls.borrow().is_empty());
        // 已取消条目再 cancel -> ScheduleNotFound
        assert!(matches!(
            s.cancel(&id),
            Err(ScheduleError::ScheduleNotFound(_))
        ));
        // 不存在的 id
        assert!(matches!(
            s.cancel("sch-999"),
            Err(ScheduleError::ScheduleNotFound(_))
        ));
    }

    #[test]
    fn snapshot_restore_roundtrip_and_expired_retrigger() {
        let mut s = Scheduler::new();
        let intent = TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap();
        let id = s
            .register(
                ScheduleSpec::At {
                    timestamp_secs: 100,
                },
                intent,
                0,
            )
            .unwrap();
        let snap = s.snapshot();
        assert_eq!(snap.entries.len(), 1);

        // 恢复后状态一致
        let mut s2 = Scheduler::restore(snap);
        assert_eq!(s2.list().len(), 1);
        assert_eq!(s2.get(&id).unwrap().next_run_secs, 100);
        assert_eq!(s2.get(&id).unwrap().state, ScheduleState::Scheduled);

        // 到期条目重载后触发
        let (mut submit, calls) = counting_submit();
        let recs = s2.tick(100, &mut submit);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].ok);
        assert_eq!(s2.get(&id).unwrap().state, ScheduleState::Fired);
        assert_eq!(calls.borrow().len(), 1);

        // next_id 恢复后继续递增，不产生重复 id
        let id2 = s2
            .register(
                ScheduleSpec::Every { interval_secs: 10 },
                TaskIntent::new("rust-build".into(), vec!["cargo".into()], None).unwrap(),
                100,
            )
            .unwrap();
        assert_ne!(id2, id);
    }
}
