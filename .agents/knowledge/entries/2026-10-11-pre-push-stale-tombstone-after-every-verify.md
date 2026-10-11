---
id: pre-push-stale-tombstone-after-every-verify
title: 同一 agent 内第二次 verify 必留 STALE 墓碑，而 pre-push 第 2 条"有 STALE 即拒推"——机制性把 agent 推向 --no-verify；rebase/force-push 还会让钩子的 range 判定失效
tags: [hooks, pre-push, evidence, stale, multi-agent, rebase, workflow-friction]
module: engineering/nexus-harness + .githooks
severity: medium
source: implementation
date: 2026-10-11
related: ["harness-dirty-digest-blind-001"]
---

## 问题描述

在一个 clone 里连跑两次 `nexus-harness verify --fast`（哪怕中间什么都没改），第二次写证据时
`mark_stale_others`（`engineering/nexus-harness/src/evidence.rs:282`）会把**同 agent scope 的
其它** evidence 目录标成 `verdict: "STALE"`。而 `.githooks/pre-push:60-86` 第 2 条规则对
`NEXUS_AGENT` 未设置的情形做的是 `grep -rl '"verdict": *"STALE"' $ROOT/.evidence`，命中即
`fail=1`（`:82` 的提示是"refresh with verify --full"）。两条规则合起来 = **正常验证流程结束时
这个 clone 已经不可能满足推送门禁**，除非人工删证据或改走 agent 命名空间。

对只做"验证 → 提交 → 推送"的 agent 来说，这是一条最容易通向
`git push --no-verify` 的路径；而删 STALE 墓碑又与"证据不可删（属人工决定）"的纪律冲突。

## 实测（xc-pc-linux, /work/hfix-verify, remote_sha 手工设为 master 176c5a5）

```
run A（留墓碑）:
  [nexus-hook] nexus-harness verify --fast = PASS
  [nexus-hook] ERROR STALE evidence found; refresh with 'nexus-harness verify --full' before pushing:
      /work/hfix-verify/.evidence/verify-1226254a5790/summary.json
  [nexus-hook] ERROR pre-push gate failed          # 该目录属于前一次 g11 分支 run（rev b9fdf8f2），
                                                   # created_at 为空 ⇒ 由 #12 的 harness 写下

run B（删掉 run A 之前的墓碑后重跑同一钩子）:
  [nexus-hook] nexus-harness verify --fast = PASS
  [nexus-hook] pre-push gate passed                # 规则 1/3/4 全通过（含 contract: marker 与 Review Evidence）
```

同一目录里另有 `verify-7359c4522211`（rev 286d8c4，PASS）与 `latest.json`。
`-stale-<hash>` 迁移目录数为 **0** —— 说明那条同 id 保全路径本轮没被触发（两次 run 的
`source_revision` 不同 ⇒ id 本就不同），STALE 完全来自 `mark_stale_others` 的跨 id 语义。

## 第二条：rebase / force-push 让 range 判定失去意义

`.githooks/pre-push:14-17` 从 stdin 取 `remote_sha`，`:91` 与 `:105` 用它拼
`range="${remote_sha}..HEAD"`，据此判断"推送范围是否触碰 protected paths / crates/*.rs"。
分支被 rebase 后，旧 `remote_sha` **不是** HEAD 的祖先，`git log remote_sha..HEAD` 要么报错、
要么把整条上游历史算进 range——门禁结论随机化。本轮两次 `--force-with-lease` 推送前都无法
用真实 stdin 复现该钩子，只能用"把 remote_sha 设成 master"的替身跑，这点要在案卷里写明。

## 解决方案（可选，均未自动实施）

1. 给每个 agent 设 `NEXUS_AGENT`，让 `:71` 的 glob 只看本 agent 的墓碑——代价是别的 agent
   留下的墓碑仍然会被无命名空间的 run 命中。
2. 钩子第 2 条改成只看 `latest.json` 指向的那一条，或只拦"本次推送 range 内引用的 evidence"，
   而不是全目录 grep。
3. 或在 `mark_stale_others` 之后由 harness 自己提示"墓碑清理属人工决定"，并把 pre-push 的
   修复建议从"verify --full"（**它只会再产一个墓碑**）改成正确的动作。

## 预防措施

- 推之前先 `ls .evidence/`，看清 STALE 是**谁的哪一次 run**留下的（读 `summary.json` 的
  `bindings.source_revision` 与 `created_at`），再决定是刷新还是删。别把"验证序列自己制造的
  墓碑"当成"证据过期"。
- 不要用 `--no-verify` 绕过；本轮做法是手工执行同一脚本、把两种结果都记进案卷。
- 引用钩子结论时写明 `remote_sha` 是**真值还是替身**（rebase 后必然是替身）。

## 参考

- 本轮案卷：`crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md` §5c
- 提交正文：`fix/nexus-harness-evidence-binding` `6a7b51d` 的"已知交互"段
- `AGENTS.md` §19/§19.1/§20（Evidence & Verdict）、`.githooks/pre-push:60-86`
