---
id: n3-scoped-operator-grants
date: 2026-10-06
module: apps/nexus
category: implementation-pitfall
task_type: feature
---

# Scoped 授权运维不能经过默认 Workspace 解析或带副作用的 KV open

## 问题与根因

既有 generic grant 经过默认 Workspace 的目录解析，不能为非 default Workspace 的已接受 N3 Task 调整 current Use。FileKvStore::open 会创建目录并清理孤儿 tmp，不适合零写入的授权取证。旧 grant 文件由调用者控制权限，可能为0644，不能误当成未知授权或直接覆盖。

## 实现边界

从显式绝对私有 config 根的 task-api.toml 读取固定 provider/workspace，直接构造真实 ResourceRef。仅复用纯 grant key/JSON 编码和 FileKvStore::file_name_for；真实文件名仍含完整 N2 key 的编码。查询不打开 N2Store、不读身份、不创建 lock 或清理 tmp。兼容在0700根中的0600/0644单链接 grant，实际变更写为0600；Manage/mixed/非canonical Use 操作不可由本入口覆盖。

变更 actor 从同根既存私有 Ed25519 seed 派生并核实记录公钥；目标 principal 字符串不是 actor 身份证据。新的固定 inode 非阻塞 lease 只串行化新入口，旧 generic/direct writer 仍需节点所有者协调。

## 持久化与取证

专用有界 hash-chain 审计先 fsync intent，再原子发布真实 grant 并同步目录，最后 fsync applied。悬空 intent、撕裂尾部或坏链阻断包括幂等请求在内的新变更；保留原 grant 与日志，查询仍可用于取证。发布后失败必须报告 mutation_may_have_applied，不能将业务 FAIL 等同于零写入。显式修复工具属于后续批次。

## Workspace 名称与编码前缀

独立审查发现 TaskId 允许斜杠，workspace `a` 与 `a/b` 的编码 grant key 前缀重叠。仅 starts_with 当前 Workspace 前缀会误读另一 Workspace，并将合法记录当作损坏。ResourceName 和 principal 不允许斜杠，因此从规范文件名右拆最后两个 `%2F`，可得到完整编码的 Workspace header；和当前 scope 的既有 FileKvStore 编码精确比较后，才读取记录、统计数量或按 resource 过滤。其他 Workspace 的坏 JSON、FIFO、symlink 或不安全权限不能阻断当前查询；当前 Workspace 的 key/content 不匹配仍失败。

## 验证注意

相同原始字节不意味着授权文件仍是读取时的文件。变更和幂等返回均须保留原始 FD，核实路径对应的 dev/ino、类型、链接数、权限与内容；原本不存在的记录须仍不存在。临时文件 fsync 后、原子发布前再次检查 scope、actor、lease、审计固定 inode 和原始 grant，避免读取后被同字节的合法私有文件替换仍成功。发布前拒绝要保留已落盘的 intent，并报告尚未应用；不可补造 applied。独立审查 R2 对此补齐了原始 inode 与两个返回边界的回归。

TaskId 的既有纯校验允许斜杠；不要凭路径直觉将其当作非法 scope。授权 key 始终经 FileKvStore 编为单文件名，不把 provider ID 用作宿主路径。非法测试应使用实际被原校验拒绝的空值、NUL 或超长 ID，并保留合法字符的正向回归。

从静态 worktree 导入源码时，保留旧 mtime 的复制可能让 Cargo 将较晚构建过的同路径缓存误认作 fresh。统一构建者应更新导入源码时间戳并再次让 Cargo 构建，保存实际 compiler-artifact 路径与二进制 SHA；源码内容 hash 不能替代实际二进制的新鲜度证明。

## 参考

- docs/N3-10-OPERATOR-GRANT-CONTRACT.md
- scenarios/product/n3-10-operator-grant.toml
