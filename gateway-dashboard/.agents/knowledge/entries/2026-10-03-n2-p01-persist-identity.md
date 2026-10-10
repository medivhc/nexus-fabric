---
id: 2026-10-03-n2-p01-persist-identity
date: 2026-10-03
module: nexus-storage / nexus-auth / apps-nexus / apps-nexusd
category: implementation-pattern
task_type: feature
---

# N2 P0-1：FileKvStore 持久基座、grant 表、LocalAPI 加固的三处可复用模式

## 模式 1：FileKvStore 落点选择（Deletion Test 的应用）

`FileKvStore`（小体量 KV＋write-ahead journal）放进 `nexus-storage` 而非新 crate
`nexus-persist` 或 `nexus-domain`，理由经 Deletion Test：
- `nexus-storage` 的 MODULE Responsibility 已明写"原子元数据更新、Journal"——新 crate
  没有独立变化维度；
- `nexus-domain` 禁止 I/O（"不执行 I/O" invariant）且 portable-core 零依赖；
- 与 `ContentStore`/FNV-1a 完全正交（新 `kv.rs`，`fs.rs` 一行不碰）。

写语义照抄 `fs.rs::atomic_write`：tmp（`create_new` 防并发覆盖）+ write + fsync(file)
+ rename + fsync(dir)。journal 尾部撕裂 fail-closed（`TornJournalTail`），必须
`journal_discard_torn_tail` 显式丢弃，不静默。

## 模式 2：LocalAPI bearer token 的两端共享

daemon（3 个 serve 路径）与 CLI 薄客户端共用
`nexus::localapi_client::load_or_create_bearer_token()`——token 文件
`~/.config/nexus/localapi.token`（0600），同一用户下两端天然一致，无需配置分发。
daemon 侧常量时间比较；缺失/错误 → 401 `UNAUTHORIZED` JSON envelope。
测试/示例（localapi_probe、daemon_workspace_mount_e4）同样调该函数取 token，
不要手写第二套 header 逻辑。

## 模式 3：worktree rsync 到真机时 `.git` 是文件不是目录

`git worktree` 的 `.git` 是指针文件（`gitdir: <主仓>/.git/worktrees/<name>`），
rsync `--exclude ".git/"`（带斜杠）只排除目录，**不会**排除该文件——会把真机上
`git init` 好的仓库覆盖回坏指针。必须用 `--exclude ".git"`（无斜杠）。
复现：真机 verify 报 `not a git repository: /home/hatch/.../.git/worktrees/...`。
