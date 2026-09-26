# nexus-scheduler Module Contract

## Responsibility

实现计划任务调度器的纯逻辑核心：时间表（`At` 一次性 / `Every` 周期）注册、
取消、列表与到期触发判定（`tick`）。触发动作不在此 crate 内执行——由组合根
注入的提交回调完成，本 crate 只负责「何时触发、触发一次、触发后如何推进」。

## Non-Responsibilities

- 不实现执行路径：不构造/提交结构化 Intent（PRODUCT §6 / §10.2），不管理
  Session / Task / Artifact。
- 不负责文件持久化：注册表序列化与落盘由组合根（apps/nexus）通过
  `SchedulerSnapshot` 完成；本 crate 提供 snapshot / restore。
- 不实现事件触发（Webhook / 文件变化 / 上游完成）、复杂日历（cron）表达式、
  daemon 常驻调度与工作流 DAG 编排（PRODUCT §14 冻结边界）。

## Inputs

- `ScheduleSpec`、`TaskIntent`（注册参数）。
- `now_secs`（i64 Unix 秒）与注入的 `SubmitFn`（触发回调）。
- 仅接受公开类型；不得依赖未声明的全局隐式状态。

## Outputs

- `Result<String, ScheduleError>`（注册返回 id）。
- `Vec<TriggerRecord>`（tick 触发结果，含成功/失败标记）。
- `SchedulerSnapshot`（序列化快照，供组合根持久化与恢复）。

## Allowed Dependencies

- 无 Nexus 内部 crate（`allowed_internal_dependencies = []`）。
- 仅标准库与 `serde`（derive / std）。

## Forbidden Dependencies

- 任何平台专有 API（portable-core，须通过 wasm32-wasip1 检查）。
- `engineering/` 下 Harness / Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。

## Invariants

- **单次触发只提交一次**：同一 tick 内对已触发条目不重复提交。
- `At` 条目触发后状态置 `Fired`，永不再触发；`Every` 条目触发后 `next_run` 前移
  且状态保持 `Scheduled`。
- 触发失败（`SubmitFn` 返回 Err）时条目保持 `Scheduled`，`next_run` 不变，
  下次 tick 重试；失败以 `TriggerRecord { ok: false }` 呈现，不静默丢弃。
- `register` 拒绝过去时间的 `At`（`at <= now`）、非正 `interval_secs` 与空命令。
- `cancel` 仅允许 `Scheduled` 条目；`Fired` / 不存在 / 已取消 → `ScheduleNotFound`。
- 幂等与恢复语义遵循 PRODUCT §14.4：崩溃后重载快照，到期未触发条目重新触发；
  重复触发风险由调用方幂等键处理（PRODUCT §10.2 / §11.3）。

## Side Effects

- 无 I/O、无平台副作用；仅内存状态变更。
- 触发副作用（提交任务）由组合根注入的 `SubmitFn` 承担，不在本 crate 内。

## Public API

### 冻结契约（PRODUCT §14，scenarios/product/schedule_flow.toml）

```rust
pub enum ScheduleSpec {
    At { timestamp_secs: i64 },
    Every { interval_secs: i64 },
}

pub enum ScheduleState { Scheduled, Fired, Cancelled }

pub struct TaskIntent {
    pub resource: String,
    pub command: Vec<String>,
    pub project: Option<String>,
}

pub struct ScheduleEntry {
    pub id: String,
    pub spec: ScheduleSpec,
    pub intent: TaskIntent,
    pub next_run_secs: i64,
    pub state: ScheduleState,
    pub fire_count: u64,
}

pub struct TriggerRecord {
    pub schedule_id: String,
    pub trigger_at_secs: i64,
    pub ok: bool,
    pub task_id: Option<String>,
    pub fire_count: u64,
    pub error: Option<String>, // 提交失败消息（SUBMIT_FAILED，可诊断）
}

pub struct SchedulerSnapshot { /* entries + next_id */ }

pub enum ScheduleError {
    InvalidSchedule(String),
    ScheduleNotFound(String),
    SubmitFailed(String),
}

pub type SubmitFn<'a> =
    Box<dyn FnMut(&TaskIntent) -> Result<String, ScheduleError> + 'a>;

pub struct Scheduler;
impl Scheduler {
    pub fn new() -> Self;
    pub fn register(&mut self, spec: ScheduleSpec, intent: TaskIntent, now_secs: i64)
        -> Result<String, ScheduleError>;
    pub fn cancel(&mut self, id: &str) -> Result<(), ScheduleError>;
    pub fn list(&self) -> Vec<ScheduleEntry>;
    pub fn get(&self, id: &str) -> Option<&ScheduleEntry>;
    pub fn tick<'a>(&mut self, now_secs: i64, submit: &mut SubmitFn<'a>)
        -> Vec<TriggerRecord>;
    pub fn snapshot(&self) -> SchedulerSnapshot;
    pub fn restore(snapshot: SchedulerSnapshot) -> Self;
}
```

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- 正常业务失败使用类型化 `ScheduleError`，不使用 panic。
- `#![forbid(unsafe_code)]`。

## Verification

最低：

```text
cargo check -p nexus-scheduler
cargo clippy -p nexus-scheduler --all-targets -- -D warnings
cargo check -p nexus-scheduler --target wasm32-wasip1   # portable-core gate
```

产品行为由 `apps/nexus/examples/schedule_flow.rs` 的 E4 场景
（`scenarios/product/schedule_flow.toml`）验证。

## Performance Budget

未定义性能预算的路径不得宣称「性能完成」。tick 为 O(n)（n = 注册条目数），
P0 面向个人 Workspace 规模，无热路径预算。

## Observability

- `list()` 与 `get()` 提供条目级状态快照（id / spec / next_run / state / fire_count）。
- `tick` 的 `TriggerRecord` 输出触发结果（schedule_id、触发时间、ok、task_id、
  fire_count、error），由组合根落入活动记录；失败触发保留错误消息供诊断。

## Recovery Semantics

- 状态权威来源：组合根持久化的 `SchedulerSnapshot`。
- 崩溃 / 重启后 `restore(snapshot)` 重建；到期未触发条目在下次 tick 触发。
- 重复触发风险遵循 PRODUCT §14.4（调用方幂等键消除），本 crate 不承诺
  exactly-once。

## Platform Constraints

- portable-core：不得调用平台专有 API；须通过 wasm32-wasip1 编译检查。
