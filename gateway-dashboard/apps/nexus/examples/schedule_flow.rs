//! E4 产品场景 `product.schedule-flow` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/schedule_flow.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example schedule_flow -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 确定性验证（虚拟时间，不依赖墙钟）：`at` 到期触发一次不重复、`every` 重排
//! 续触发、`cancel` 阻止触发、注册表保存 / 重载状态一致且到期条目重载后触发。
//! 提交回调由注入的闭包承担（PRODUCT §14.2），统计总提交次数。

#![forbid(unsafe_code)]

use nexus_scheduler::{ScheduleSpec, Scheduler, SubmitFn, TaskIntent};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::rc::Rc;

/// 构造执行意图（resource + command + 可选 project）。
fn intent(resource: &str, command: &[&str], project: Option<&str>) -> TaskIntent {
    TaskIntent::new(
        resource.to_string(),
        command.iter().map(|s| s.to_string()).collect(),
        project.map(str::to_string),
    )
    .expect("intent must be valid")
}

/// 计数提交回调：每次调用 total+1，task id 取递增序号。
fn make_submit(total: &Rc<RefCell<u64>>) -> SubmitFn<'static> {
    let counter = total.clone();
    Box::new(move |intent: &TaskIntent| {
        *counter.borrow_mut() += 1;
        let n = *counter.borrow();
        Ok(format!("task-{}-{n}", intent.resource))
    })
}

/// 跑一遍计划任务闭环，返回单个 JSON 对象。
fn run() -> Result<Value, Box<dyn std::error::Error>> {
    // 全局提交计数器：所有 tick 的提交都计入（断言 total_calls）。
    let total = Rc::new(RefCell::new(0u64));

    // ---- 1. at：到期触发一次，后续不重复 ----
    let at_result = {
        let mut s = Scheduler::new();
        let id = s.register(
            ScheduleSpec::At {
                timestamp_secs: 100,
            },
            intent("rust-build", &["cargo", "test"], Some(".")),
            0,
        )?;
        let mut submit = make_submit(&total);

        let before = s.tick(99, &mut submit); // 未到期：不触发
        let fired = s.tick(100, &mut submit); // 到期：触发一次
        let after = s.tick(200, &mut submit); // 已 Fired：不重复

        let fired_once = before.is_empty()
            && fired.len() == 1
            && fired[0].ok
            && fired[0].schedule_id == id
            && fired[0].task_id.is_some();
        let no_duplicate = after.is_empty();
        let state_after_fire = match s.get(&id).map(|e| e.state) {
            Some(nexus_scheduler::ScheduleState::Fired) => "Fired",
            _ => "UNEXPECTED",
        }
        .to_string();
        json!({
            "fired_once": fired_once,
            "no_duplicate": no_duplicate,
            "state_after_fire": state_after_fire,
        })
    };
    if !(at_result["fired_once"] == json!(true)
        && at_result["no_duplicate"] == json!(true)
        && at_result["state_after_fire"] == json!("Fired"))
    {
        return Ok(verdict_fail("at", at_result));
    }

    // ---- 2. every：触发后重排 next_run，保持 Scheduled 并续触发 ----
    let every_result = {
        let mut s = Scheduler::new();
        let id = s.register(
            ScheduleSpec::Every { interval_secs: 50 },
            intent("rust-build", &["cargo", "build"], None),
            0,
        )?;
        let mut submit = make_submit(&total);

        let first = s.tick(50, &mut submit); // 触发 1，next_run -> 100
        let rescheduled = first.len() == 1
            && first[0].ok
            && s.get(&id).map(|e| e.next_run_secs) == Some(100)
            && s.get(&id).map(|e| e.state) == Some(nexus_scheduler::ScheduleState::Scheduled);
        let second = s.tick(100, &mut submit); // 触发 2，next_run -> 150
        let second_ok = second.len() == 1 && second[0].ok;
        let fire_count = s.get(&id).map(|e| e.fire_count).unwrap_or(0);
        let state_stays_scheduled = match s.get(&id).map(|e| e.state) {
            Some(nexus_scheduler::ScheduleState::Scheduled) => "Scheduled",
            _ => "UNEXPECTED",
        }
        .to_string();
        json!({
            "rescheduled": rescheduled,
            "fire_count": fire_count,
            "state_stays_scheduled": state_stays_scheduled,
            "second_ok": second_ok,
        })
    };
    if !(every_result["rescheduled"] == json!(true)
        && every_result["fire_count"] == json!(2)
        && every_result["state_stays_scheduled"] == json!("Scheduled"))
    {
        return Ok(verdict_fail("every", every_result));
    }

    // ---- 3. cancel：取消后即使到期也不触发 ----
    let cancel_result = {
        let mut s = Scheduler::new();
        let id = s.register(
            ScheduleSpec::At {
                timestamp_secs: 100,
            },
            intent("rust-build", &["cargo", "test"], None),
            0,
        )?;
        s.cancel(&id)?;
        let mut submit = make_submit(&total);
        json!({ "blocked_fire": s.tick(200, &mut submit).is_empty() })
    };
    if cancel_result["blocked_fire"] != json!(true) {
        return Ok(verdict_fail("cancel", cancel_result));
    }

    // ---- 4. 持久化：保存 -> 重载状态一致；到期未触发条目重载后触发 ----
    let persist_result = {
        let mut s = Scheduler::new();
        let id = s.register(
            ScheduleSpec::At {
                timestamp_secs: 100,
            },
            intent("rust-build", &["cargo", "test"], Some(".")),
            0,
        )?;
        let snap = s.snapshot();

        // 模拟崩溃 / 重启：从快照恢复。
        let mut s2 = Scheduler::restore(snap);
        let reload_state_matches = s2.list().len() == 1
            && s2.get(&id).map(|e| e.next_run_secs) == Some(100)
            && s2.get(&id).map(|e| e.state) == Some(nexus_scheduler::ScheduleState::Scheduled)
            && s2.get(&id).map(|e| e.fire_count) == Some(0);

        let mut submit = make_submit(&total);
        let recs = s2.tick(100, &mut submit);
        let expired_reloaded_fired = recs.len() == 1
            && recs[0].ok
            && s2.get(&id).map(|e| e.state) == Some(nexus_scheduler::ScheduleState::Fired);

        json!({
            "reload_state_matches": reload_state_matches,
            "expired_reloaded_fired": expired_reloaded_fired,
        })
    };
    if !(persist_result["reload_state_matches"] == json!(true)
        && persist_result["expired_reloaded_fired"] == json!(true))
    {
        return Ok(verdict_fail("persist", persist_result));
    }

    // at(1) + every(2) + 重载到期(1) = 4；cancel 的不触发。
    let total_calls = *total.borrow();
    if total_calls != 4 {
        return Ok(verdict_fail(
            "submit",
            json!({ "total_calls": total_calls, "expected": 4 }),
        ));
    }

    Ok(json!({
        "verdict": "PASS",
        "command": "schedule-flow",
        "at": at_result,
        "every": every_result,
        "cancel": cancel_result,
        "persist": persist_result,
        "submit": { "total_calls": total_calls },
    }))
}

/// 失败 JSON：verdict=FAIL + 定位失败的检查点。
fn verdict_fail(section: &str, extra: Value) -> Value {
    let mut v = json!({ "verdict": "FAIL", "command": "schedule-flow" });
    v[section] = extra;
    v
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let v = value["verdict"].as_str().unwrap_or("FAIL");
                let calls = value["submit"]["total_calls"].as_u64().unwrap_or(0);
                println!("schedule-flow OK: verdict={v}, total_calls={calls}");
            }
        }
        Err(err) => {
            eprintln!("schedule_flow example failed: {err}");
            std::process::exit(1);
        }
    }
}
