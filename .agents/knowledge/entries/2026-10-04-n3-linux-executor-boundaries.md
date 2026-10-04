---
id: n3-linux-executor-boundaries
date: 2026-10-04
module: apps/nexusd
category: implementation-pitfall
task_type: feature
---

# Docker tmpfs、私有输入与控制/日志并发不能只凭配置推断

本环境宿主 UID 1000。容器 root 在 cap-drop=ALL 时不能绕过宿主 0700/0600 权限；
应由 Provider 私有 0700 父目录保护只读传递子树，显式设置其读取权限，不能依赖
create mode（umask 可能收紧到 0600）。挂载 kernel readonly，命令保持非 root/无 capabilities。

Docker archive PUT 对 readonly-rootfs 即使 tmpfs 目标也拒绝；archive GET 的重建根
未包含本环境真实运行 tmpfs 数据。不能据此误判输入/输出不存在。输入经受控 cp
进入硬配额 tmpfs，工作树由容器内固定 tar 直接导出，先检查 inventory，再暂存明确输出。
避免用需要特权的宿主 /proc/<pid>/root 作为默认路径。

大输出时，先读一块日志再阻塞控制查询会使 Engine I/O 和查询互相等待。
日志 reader 必须独立持续 drain、达到保留限额后继续读取，且由调用 owner 在 scope
结束前 shutdown/join。真实 2 MiB 输出、4 KiB 保存上限的失败回归验证了这个边界。

自然主进程退出不等于所有后代退出：清理同 UID 后代、核实无活跃者后才能冻结输出；
namespace 全部停止/reap 后才确认取消/超时。kill(-1) 必须先确认私有 PID namespace，
并通过固定镜像工具执行，绝不能把该操作放在宿主 namespace。

跨进程 owner lease 释放不等于 Kernel 进程结束。SIGKILL 后保留 Engine ID、原始
单调预算证明及任务标签，标记待核实并阻断新执行；未知时不猜终态、不自动重跑。

参考：docs/N3-3-LINUX-EXECUTOR.md；.evidence/n3-3-executor/。
