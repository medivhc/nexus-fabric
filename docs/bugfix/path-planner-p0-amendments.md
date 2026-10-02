# Contract Amendments — bugfix/path-planner-p0（T1，P0 四 bug）

基线：master `437b5da`（contract hash `686cf602148de4b7a148d86f5118dc0d266480d2`）。
类型：bugfix。默认保持产品契约与 Scenario expectation 不变；以下四条为行为变更点
（D3/D4 为 2026-10-03 用户拍板决策）。不重写整份合同。

---

## A1. planner：未知 RTT 严格排最后（D3）

- 文件：`crates/nexus-planner/src/lib.rs`（`score_candidates`）
- 契约文字：**不动**（D3 明确要求）。
- 行为变更点：排序键显式区分已知/未知 RTT。**任何携带有效 RTT 测量的候选恒排在
  无测量候选之前**，与分数无关；同类内部保持旧规则（分数降序，同分按 ProviderId
  字典序）。`max_rtt == 0`（全未知）时保持旧行为：全 0 分、按 id 字典序。
- 旧行为（bug）：未知 RTT 经 `.map_or(0, …)` 得 0 分，与最慢已知 RTT（归一化亦为 0）
  同分，tie-break 只看 id 字典序 → id 更小的未知候选会排到已测候选前面，
  违背注释与测试名"未知 RTT 排最后"的语义。
- Red Evidence：单测 `unknown_rtt_strictly_sorts_last`
 （`aaa-unknown` 无测量 vs `zzz-measured` rtt=50ms）：旧代码选出 `aaa-unknown`（FAIL），
  修后选出 `zzz-measured`（PASS）。既有测试 `unknown_rtt_sorts_last_and_tie_breaks_by_id`
 （全未知→按 id）与 `unknown_rtt_scores_zero_and_sorts_last` 语义保持，继续通过。

## A2. path：`PathEvent::Adopted`（D4）

- 文件：`crates/nexus-path/src/lib.rs`
- 契约变更点（MODULE.md 同步更新）：
  - `Public API`：`PathEvent` 新增变体 `Adopted { to: CandidatePath }`
   （字段与 `Switched` 的 `to` 同构）。
  - `Outputs`：新增 `PathEvent::Adopted { to }` —— manager 在此前无活跃路径
    （`active == None`）时收养最优已知候选为活跃路径时发射。不是 switch
   （无 `from`）。
  - S9 补充：`Switched` 仍是 from→to 切换的唯一信号；`Adopted` 覆盖
    None→active 的收养。应用层/pump 必须排空两种事件。
- 行为变更点：`evaluate()` 的 `active == None` 分支此前静默收养
  （注释 "Not a switch, no event"），现发射 `Adopted { to }`。
  PathLink 侧对 `Adopted` 的语义处理由 T3 轨道完成（本分支仅保证工作区可编译，
  `path_link.rs::handle_event` 暂按 `Switched` 的 `to` 侧同构处理，标 TEMPORARY）。
- Red Evidence：单测 `adopt_emits_adopted_event`：旧代码 `poll_event()` 返回
  `None`（FAIL），修后返回 `Adopted { to: Direct }`（PASS）。
- 连带更新（行为变更的诚实代价）：以下既有单测在 setup 期会先收到 `Adopted`
  事件，测试意图（switch 语义）不变，仅在断言前排空收养事件：
  `hysteresis_hold_then_switch`、`missed_probes_trigger_immediate_failover`、
  `hysteresis_blocks_small_margin`、`nat_peer_relay_beats_direct`、
  `nat_direct_wins_when_much_better`。未改任何 expected value。

## A3. path：`add_candidate` 重申保留观测（bug 3）

- 文件：`crates/nexus-path/src/lib.rs`（`add_candidate`）
- 契约文字：MODULE.md 未逐字规定重申语义；本条将其冻结为：
  重申已存在的 candidate（同 `remote_addr`）**保留**其 `ewma` 观测与
  `missed_probes` 计数（与既有"保留 `added_at` 防伪造 newness"同理），
  只替换 `CandidatePath` 描述体（kind/addrs/cost 可更新）。
- 行为变更点：旧代码对已存在 remote 直接重建 `PathEntry`，
  `ewma`/`missed_probes` 清零 → 随后 `evaluate` 的未知分分支直接
  `do_switch(BetterScore)`，绕过 20% hysteresis + switch_hold。
- Red Evidence：
  - `reannounce_keeps_ewma`：加分→重申→`score()` 仍为旧值；旧代码返回 `None`（FAIL）。
  - `reannounce_keeps_missed_probes`：2 次 miss→重申→第 3 次 miss 触发 S6 failover；
    旧代码计数被清零、不切换（FAIL）。

## A4. path：`best_candidate` 排除已判失败路径（bug 4）

- 文件：`crates/nexus-path/src/lib.rs`（`best_candidate`）
- 契约变更点（S6 补充）：被判失败的路径（`missed_probes >= max_missed_probes`）
  在收到新的有效观测（清零 miss 计数）之前，**不参与选优**；
  与 S6"连续 miss 达阈值即判失败"对齐，防止死路径凭陈旧高分被选回造成 flap。
- 行为变更点：`best_candidate` 过滤条件从仅 `ewma.value().is_some()` 增加
  `missed_probes < max_missed_probes`。
- Red Evidence：单测 `dead_path_not_reselected_on_stale_score`：
  direct 高分→3 次 miss→failover 到 turn→hold 走完后旧代码切回已死的 direct（FAIL），
  修后保持 turn（PASS）；随后 direct 收到有效报告恢复参选并赢回（恢复语义不断）。
