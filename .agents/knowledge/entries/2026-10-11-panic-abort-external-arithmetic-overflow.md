---
id: panic-abort-external-arith-001
title: 外部可控的 offset+len 算术溢出 × release panic="abort" = 一条畸形帧 SIGABRT 整个节点
tags: [arithmetic-overflow, panic-abort, catch-unwind, worker-thread, release-profile, fuzz]
module: nexus-web-gateway
severity: high
source: review
date: 2026-10-11
related: ["unwrap-or-eager-001", "resource-quota-audit-gate-001"]
---

## 问题描述

`src/file.rs:1387` 用 `offset + len` 计算本片结束偏移并据此校验 `max_upload_bytes`。
`offset`/`len` 都来自浏览器可控帧。评审真跑（角度 4、6）观察到两种构建下的**不同故障形态**：

- **debug/test 构建**：`attempt to add with overflow` panic ⇒ worker 线程静默死亡，
  **ack 丢失、不发 `Closed`、`file_sessions` 假活**。放大因素：全 crate 8 处 `thread::spawn`
  （`gateway.rs:503,507,522,997,1256,1575,1674,1919`）**全部丢弃 `JoinHandle`，无 `catch_unwind`**，
  所以没人知道线程死了。
- **release 构建**：overflow-checks 关闭 ⇒ 回绕成小值，**反而通过 `max_upload_bytes` 检查**，
  配额被绕过。
- 根 `Cargo.toml:68` 的 workspace release profile 是 **`panic = "abort"`** ⇒ 任一 worker panic
  变成**整个网关进程 SIGABRT**（实测 exit 134）。暴露面一句话：**一条畸形帧杀死该节点全部
  终端/文件/信令会话**。

## 根因分析

三条独立假设同时不成立：

1. "溢出会 panic 所以安全"——panic 只在 debug 存在，release 是回绕，而回绕**放宽**了校验；
2. "worker 崩了不影响别人"——`thread::spawn` + 丢弃句柄，在 `panic=abort` 下不但影响，而且是全进程；
3. "`catch_unwind` 是防线"——**发布版根本没有这条防线**（abort 不展开）。把隔离寄托在它身上是自我安慰。

## 解决方案

V2 设计（`GATEWAY-FILE-SERVICE-DESIGN-V2.md` §4）的立场是"承认 unwind 无效，改为构造性无 panic"：

- 所有 `offset + len` 收敛到一个函数 `checked_end(offset: u64, len: usize) -> Result<u64, FileError>`，
  连带推进点（`:1404/1432/1440`）一起改；配 **模块级 clippy `arithmetic_side_effects = "deny"`**
  把纪律机器化，不靠人眼。
- worker 结构化：保存 `JoinHandle` 入 `FileBridge`，线程体包
  `catch_unwind(AssertUnwindSafe(run_file_worker))`；事件循环检测 `is_finished()` 且结果 `Err(_)`
  ⇒ 向该浏览器会话投 `FileClosed{reason:"worker_panic", code:"WORKER_PANIC"}` 并清理其句柄/流/缓冲
  （对应 AGENTS.md §13 结构化并发、§14 恰一次终态）。**明确定位为 debug/test/CI 的探针**，不是发布版防线。
- **panic-free by construction**：外部输入路径禁 `unwrap/expect`（`decode_frame` 现存两处
  `expect("checked length")`，`file.rs:132-133` 属"先判长度后取"，列入审计清单）；
  帧解码 / 配额判定 / 分页裁剪写成 total 风格纯函数并用 **fuzz** 覆盖 `decode_frame + stage_chunk`；
  debug 的 overflow-panic + `catch_unwind` 测试当作"发布前会红"的探针用。
- 是否为网关宿主二进制改用 `panic = "unwind"`（体积换隔离）列为待决策 **D7**，本设计默认接受现状。

## 预防措施

- Review 看到**来自浏览器/对端/文件的数值**参与 `+ - *`，一律要求 `checked_*` 或 `saturating_*`，
  并追问"release 下回绕会**放宽**还是**收紧**安全判定？"——这里是放宽（绕过配额）。
- 任何 `thread::spawn` 都必须有归属：句柄要存、终态要投递；否则"线程静默死亡"= 上层状态假活。
- **读一次根 `Cargo.toml` 的 profile**：`panic = "abort"` 意味着 debug 与 release 的失败语义不同，
  关于 panic 的所有推理都要分构建讲。别在案卷里声称 `catch_unwind` 保护了发布版。
- 变异必红清单里要有一条：`checked_add → +` 必须让测试红（用 `offset = 2^64-1` 用例）。
- 同类既有经验：`unwrap-or-eager-001`（`unwrap_or` 参数立即求值导致减法下溢 panic）——
  **panic 的来源常常就是"外部可控数 + 无 checked"**。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` P0-4（:66-71）
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §4（A4）、§10（变异清单）、§12 D7
- 根 `Cargo.toml:68`（`panic = "abort"`）、`src/file.rs:1387`、`src/gateway.rs` 8 处 spawn
