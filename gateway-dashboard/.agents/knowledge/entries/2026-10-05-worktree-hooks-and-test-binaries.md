---
id: worktree-hooks-test-binaries
date: 2026-10-05
module: .githooks / engineering/nexus-harness
category: implementation-pitfall
task_type: bugfix
---

# Git 钩子环境和真实测试二进制必须归属当前 worktree

## 已复现的问题

N3-6 同步 master 时，中心 hook wrapper 再次加载固定主仓库的 activate，覆盖了
当前 worktree 的 target/config/token/home/PATH；因此 PATH 可能选中旧 Harness。
即使直接执行仓库 hook，Git push 导出的 GIT_DIR 被 Cargo 测试继承，六个
Harness 测试把 engineering/nexus-harness 当作仓库根，读取不到 harness.toml。
独立注入 GIT_DIR 稳定复现 34PASS/6FAIL，清除后同源40tests通过。

CLI 集成夹具另依赖当前 nexus/nexusd 两个真实可执行文件。cargo check/clippy
只检查类型，不保证生成这两个文件；测试内部再跑 Cargo 会与外层 test 争用锁。
Harness 曾递归把 tests/helper/mod.rs 误当 --test mod，Cargo 实际未声明该目标。

## 工程原则

- 保留 hook 对真正 index/HEAD 的检查上下文；只为执行测试的子进程清理 Git
  repository-local 环境，使其从自己的工作目录发现仓库。
- 当前 Cargo workspace 构建并运行当前 Harness；明确处理 linked worktree
  继承主仓库默认 target 的情况，保留调用方其他显式配置。
- 安装按 worktree 作用域配置 hooks，避免意外修改所有并行工作区。
- Harness 先构建当前 CLI/daemon，从 Cargo artifact 取 executable，再注入测试
  Command 的环境。失败必须报告，不使用旧 master 输出补位。
- 测试目标由 Cargo metadata kind=test/name 确定；源码辅助文件不是独立目标。
- 工程 fake-tool 夹具与真实产品链分别标记证据强度；不把预构建等价为 Task 完整可用。

## 参考与验证范围

基线7933f1c；历史红灯/绿灯在 N3-6 remote-sync 交付目录；本批证据在
`.evidence/n3-7/`。N3-7计划：`docs/N3-7-ENGINEERING-PLAN.md`。
最终是否修复以当前源的独立 Review 和原生 Fast/Full 为准；原网络失败与
缺完整N3 verifier的状态另行保留。Submit/下载能力不因工程修正自动开放。

## 归档二进制的修正

源目录 SHA 与旁边归档 binary SHA 均匹配，仍不能证明 binary 由该源构建。
N3-7 发现留存 basic 输出 packets/reverse，而当前 verifier 要求 stream/datagrams/RTT；
因此旧三个 PASS 观测不能认证当前场景。应以当前 Cargo compiler-artifact 路径、
构建记录与源码字节摘要共同建立出处；旧观测及更正须同时保存。
并发冷节点身份生成会产生多个 seed，导致握手看到的公钥与签名密钥不一致。
16并发回归明确复现后，首次创建由同进程锁和二次读取保护；已有身份读取不加锁。
保留原冷 idle-client 测试，不用预初始化夹具掩盖竞态；跨进程初始化仍需节点所有者协调。
