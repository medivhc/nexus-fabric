---
id: scoped-lease-inherited-fd
date: 2026-10-19
module: apps/nexusd / nexus-platform-linux
category: implementation-pitfall
task_type: bugfix
tags: [concurrency, flock, ownership, recovery]
---

# CLOEXEC 不保证私有短期租约在父作用域结束时释放

Linux flock 归属于 open file description。CLOEXEC 在 exec 时关闭描述符，
不会阻止无关线程创建的 fork/vfork 子进程在 exec 前短暂继承它。
父作用域仅 close 自己的 File 后，子进程仍可保留这把锁，导致新的独立 open
非阻塞加锁返回 WouldBlock。不能把每次报忙都当作仍有合法业务 owner。

N3-12 验证的原 scope 阶段失败没有 syscall trace，精确原因仍 UNKNOWN；
受控同一 ELF 在 preflight 阶段的失败则有完整 open/flock/clone/close/exec
顺序证明该继承机制。不同 phase、mutation flag 的失败不能合并成同一签名。

私有 N3-11 短期 Lease 的候选修复在逻辑操作结束时显式释放同一 OFD 的锁，
包括成功加锁后返回 retryable Err 的分支。通用 File 克隆及最后关闭语义保持，
长期 capacity/executor owner 未作全局改动。显式释放会影响共享该 OFD 的全部
克隆/继承描述符，只能由确认保护操作已结束的逻辑 owner 调用；不能推广成
“任意 File drop 都 unlock”。Drop 不能传播错误或在 unwind 时再次 panic。

回归应采用确定性继承屏障而非 sleep/retry：将克隆 FD 安装到单一 owned child
的 stdin，核对其存活和 /proc/fd inode；私有 owner 退出后 child 仍活时重获，
再验证旧 child 退出不解除新独立 owner 的锁。正常、Err 和 unwind 同时覆盖
新建及既存非空锁，精确检查原字节/inode/mode/nlink/root；保留 raw clone
最后关闭控制。所有 child 必须在断言 panic 时也 kill/wait。

本组独立测试评审 R2 APPROVED；旧实现 6 RED/4 控制 PASS，修复后 10 PASS。
这些局部事实不替代当前组合的 Fast、独立代码 Review 或 Full。

参考：`.evidence/n311-lease-busy-diagnosis-20261018/`、
`.evidence/n3-12/lease-adoption-20261019/` 与原 N3-11 初始化契约。
