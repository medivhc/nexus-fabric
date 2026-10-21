---
id: harness-dirty-digest-blind-001
title: dirty 态 working_tree_digest 是 git status --porcelain 文本的 hash，对文件内容盲；evidence id 可被异内容树覆写
tags: [harness, evidence, working-tree-digest, git, traceability]
module: nexus-harness
severity: high
source: review
date: 2026-10-11
related: ["cli-unify-scenario-requirement-change-pattern", "pre-push-stale-tombstone-after-every-verify"]
---

> **状态：已修，待合入（2026-10-11 更新，取代本条立案时的"待确认"）。**
> 修复在分支 `fix/nexus-harness-evidence-binding`（tip `6a7b51d`，叠在
> `fix/gateway-ice-candidate-bind` `e1ef70c` 上）。xc-pc-linux 实测：
> 同一棵脏树只改未跟踪文件的字节，master 二进制 digest 恒为
> `af614e393b66767ff48d5b5ab6957c09b21e58b4`，修复后二进制由
> `cda75a5986058a748b905153313a69d6ceff874d` 变为 `d56c65795d512c68da6d393a38a87bdd0ce48c35`。
> 在分支合入 master 之前，master 上产生的 dirty 态 evidence **仍按本条原语义打折**。

## 问题描述

`cargo run -p nexus-harness -- verify --fast` 在**未提交的工作树**上产出 evidence
`verify-c327a6da9351`（记录 `source_revision 0576cb73…`、`dirty_state true`、`contract_hash 8de98ae1…`）。
问题是：**这条 evidence 不能证明任何具体字节被验证过。**

评审 #17 实测：dirty 态下修改 `static/app.js` 的**内容**，`working_tree_digest` 不变
（仍是 `0e2ebec4…`）；只有 `git add -A` 之后才变（`fc55d63d…`）。

## 根因分析

源码语义（`engineering/nexus-harness/src/env.rs`）：

- clean 态用 `git write-tree`（内容敏感，正确）；
- **dirty 态用 `git status --porcelain` 文本的 hash**，注释自陈 "stable for a given dirty state"
  ⇒ 它只锁定"哪些路径处于什么状态"，**对文件内容完全盲**；
- `evidence.rs:62-70`：evidence id = `hash(revision | config | contract)`，
  **既不含 digest 也不含时间戳** ⇒ 另一棵内容完全不同的树可以以**同一个 id** 覆写 evidence。

顺带的纠正：先前案卷写"`working_tree_digest` 疑似只看 git index"——**指认不准确**，
真实机制是上面这条（dirty 走 porcelain 文本）。这类"猜测式指认"本身也是要沉淀的教训。

## 解决方案

原提案三条，落地时**第 2 条只实现了一半**，取舍要写清楚以免后人照抄提案：

1. ✅ dirty 态改为对**内容**做 hash：`hash(git diff HEAD --binary ⊕ 未跟踪文件 "path oid" 排序表)`，
   经 `git hash-object --stdin`（字节安全的新 `git_bytes`/`hash_stdin_bytes`，因为 `git()` 的
   整段 `trim()` 会剥掉 porcelain 首行 ` M` 的前导空格）；clean 态保持 `git write-tree`；
   unborn branch 退为 `ls-files -s ⊕ git diff --binary`。
2. ⚠️ evidence id 现在**只在 `dirty_state != Some(false)` 时**把 digest 纳入 seed，
   **时间戳不进 id**（提案曾写"至少包含 digest 与时间戳"）。理由：`.evidence/` 是入库对象，
   AGENTS.md 与技能文档以 `verify-<id>` 作可追溯标识，时间戳进 seed 会让每次 run 都换目录、
   文档引用当场失效、跨机不可复现；墙钟改记在 summary 的 `created_at` 字段。
   干净树/CI 的 id 因此逐字节不变（向后兼容实测成立），脏树则"每份内容一个 id"；
   git 问不出脏净的 `None` 也进 seed（带哨兵 digest），既不折叠成"干净树 id"
   也不与任何真实内容 id 相同。同 id 但 bindings 不同的旧证据先整体迁到
   `verify-<id>-stale-<hash>` 再写，不再被 `fs::write` 静默抹掉。
3. ✅ 引用纪律保留；`harness.toml` 的 `[evidence].bind_working_tree_digest` 由死配置变为
   `Bindings::current(&Repo, &Config)` 的兑现点（false ⇒ `"unbound"`，缺省 true）。

已知代价（实测）：干净树 `status` 22 ms vs 23 ms（CI 路径无回退）；脏树 200 个未跟踪文件
22 ms vs **133 ms**（每文件一次 `git hash-object` 子进程，随未跟踪文件数线性增长）。
若成为负担，收口方向是 `git hash-object --stdin-paths` 批量取 oid。

## 预防措施

- 引用 evidence 时，先问三件事：**它绑定了 revision 还是也绑定了工作树内容？dirty_state 是什么？
  id 的哈希输入里有没有 digest 与时间戳？** 三问有一个答不上来，就不要用它背书具体字节。
- 未提交的改动**没有远端证据**：本次 `gateway-ci` 只在 push master 时触发，master HEAD 的 run 仍
  failure，看板 artifact 断链实测仍在——"CI 会变绿"属推测。完成判据应含"一次真实 push 触发的 CI 绿"，
  不接受本地复述（该纪律已写进 V2 §10/§11 的退出准则）。
- 对本仓库其他 harness 结论的迁移检查：凡历史上引用 dirty 态 evidence 的案卷，其"验证了什么"的
  范围都要重新按内容盲的语义打折。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §5（公开更正，:89-96）
- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` §5 第 1 条、角度 17（COMMENTED）
- 源码：`engineering/nexus-harness/src/env.rs::working_tree_digest`、`src/evidence.rs:62-70`
- 待关联：harness 立案条目（另一 agent 独立复核中，结论出来后补 `related` 与定案表述）
