---
id: ws-w4-cache-fuse
date: 2026-10-02
module: nexus-workspace / nexus-platform / nexus-platform-linux
category: architecture-decision
task_type: feature
---

# W4：CacheManager + FUSE 投影——trait 选址与真机踩坑

## 决策：ProjectedWorkspace trait 放 nexus-platform

`WorkspaceAccess` 已在 nexus-workspace 冻结，不能搬。`nexus-platform-linux`
直接依赖它会违反 v9 §4 "platform adapters -X-> higher-level domain
runtimes"。所以：

- portable trait `ProjectedWorkspace` 放 `nexus-platform`（portable trait 层）；
- `nexus-workspace` 提供 `WorkspaceProjection<A>` 适配器
  （domain → portable 方向，已有先例，architecture.toml 已声明）；
- `nexus-platform-linux` 的 FUSE 只消费 trait。

Deletion Test：删掉 trait，platform-linux 直连 workspace 会破坏架构不变量，
且 Windows/macOS/Android/iOS 每个平台要各写一份私有耦合。

## CacheManager 设计要点

- 确定性逻辑时钟（tick），无平台时钟依赖， portable。
- 评分公式：`(hits+1)*(1+ws_prob)*(1+centrality)*(1+refetch_cost) / (size*(1+age))`，
  从低到高驱逐；平局按 insert_tick、key 排序——完全确定性。
- `insert` 永不把刚插入的 key 当牺牲品：腾不出空间就回滚并报
  `PinnedCapacityExceeded`（静默自驱逐是 no-op 谎言）。
- W2 的 WorkingSet Probability 是可选信号（`set_workingset_probability`），
  永不做正确性依赖；缺 key 时返回 false 不 panic。
- Cache Eviction ≠ CAS GC：只丢缓存副本；pin 分类与 §20 Protected Roots
  同口径，W1 对齐用。

## FUSE 真机踩坑（xc-pc-linux，两个都是 E4 抓到的真 bug）

1. **open 忽略 O_TRUNC**：`std::fs::write` 覆盖写时，buffer 里还是旧内容，
   offset 0 写 "v2" 得到 "v2lo fuse"。修：open 时检查 `flags.0 & 0o1000`，
   截断 buffer 并标 dirty（无后续 write 也要 flush）。
2. **setattr 无 fh 的截断与 open buffer 分叉**：内核 O_TRUNC 走
   `do_truncate` → FUSE_SETATTR **不带 fh**，我的旧代码对 workspace 副本
   做 read-modify-write，但 open 的 buffer 里还是旧数据，release 时又写回
   旧数据。修：setattr 截断先同步该 path 的所有 open buffer，无 open 才
   走 read-modify-write。

## fuser 0.18 API（与记忆不符处）

- `Filesystem` 方法是 `&self`（不是 `&mut self`）；`INodeNo`/`FileHandle`
  是 newtype；`reply.error()` 吃 `Errno`（不是 i32）。
- `spawn_mount2` 不存在，是 `spawn_mount(fs, path, &Config)`；
  `Config { mount_options: Vec<MountOption>, .. }`。
- `FUSE_ROOT_ID` 不存在，root ino 就是 1。
- `AutoUnmount` 需要 AllowOther/AllowRoot，否则 mount 失败——E4 不用它，
  靠 drop session 卸载。
- `OpenFlags(pub i32)` 是 tuple struct，直接读 `.0`。

## 可复用要点

- 真机 FUSE 不需要 sudo（/dev/fuse 是 crw-rw-rw-），fusermount(1) 在。
- E4 挂载点用 pid 隔离的 tmpdir，测完 drop session + rmdir，无残留。
- 沙盒无 /dev/fuse：example 输出 verdict=SKIP，scenario 用
  `one_of = ["PASS", "SKIP"]`（os_assemble 模式）。
