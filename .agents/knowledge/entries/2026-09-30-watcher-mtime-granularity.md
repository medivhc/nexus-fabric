# mtime 不能作为文件变化检测的决定条件（粗粒度时间戳）

日期：2026-09-30
阶段：bugfix（strategy_watcher 基线修复，用户授权）

## 发生了什么

`apps/nexus/src/strategy_watcher.rs` 的 `poll_once` 用 `mtime == baseline.mtime → 静默跳过`
作为变化检测。xc-pc-linux 的 `/tmp` 上连续写入的 mtime **完全相同**
（实测：两次连续写 tv_sec/tv_nsec 一致；紧循环 100 次写入 99 次 mtime 不变），
导致 3 个 watcher 集成测试在真机上 5s 超时失败（沙箱时间戳粒度细，全过）。

## 根因

文件系统时间戳粒度是环境属性，不是逻辑保证。`lazytime` 挂载选项或
粗粒度时钟下，mtime 在短时间窗口内不更新。任何"mtime 未变 ⇒ 内容未变"
的推论都是错的。

## 修复（`bugfix/watcher`，commit d36e70c）

- `poll_once`：mtime 降级为**提示**，每次轮询都读文件做 FNV-1a 内容哈希对比；
  哈希才是真相来源。配置文件很小（TOML 几百字节），每 50ms 一次读+哈希
  开销可忽略。
- 保留原有语义：内容不变 → 静默跳过（无论 mtime 是否变化），因此
  `watcher_ignores_content_unchanged_rewrite`（mtime 变、内容不变 → 零事件）
  继续通过。
- 新增回归单测 `poll_once_detects_change_when_mtime_unchanged`：构造
  mtime 与文件当前相同、但哈希/策略过期的基线，直接调 `poll_once`，
  断言仍能检测到并应用策略变化。不依赖文件系统行为，任何平台可跑。

## 验证

- xc-pc-linux：`--test strategy_watcher` 6/6 PASS（修复前 3 失败）；
  `--lib` 38/38 PASS；`strategy_watcher` example 输出 `verdict: PASS`；
  `cargo fmt --check` clean。
- 沙箱：同样全过。

## 教训

1. 基于 mtime 的变化检测必须配内容哈希兜底；**mtime 只能做快速路径，不能做决定**。
2. 时序/文件系统相关的测试失败，先在失败环境复现并用最小探针
   （如 mtime 写入探针）定位，不要在通过的环境里猜。
3. 这类失败具有"环境特异性"：沙箱过、真机挂。报告时要明确说出
   差异点（时间戳粒度），而不是笼统的"时序问题"。
