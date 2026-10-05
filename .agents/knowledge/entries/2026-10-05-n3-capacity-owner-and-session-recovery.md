---
id: n3-capacity-session-recovery
date: 2026-10-05
module: apps/nexusd / nexus-compute
category: implementation-pattern
task_type: requirement-change
---

# 容量 Ready 需要活 owner，Session 清理需要原 Manager 的持久证据

## 问题与根因

接受合同中的字符串 reservation ID 不证明真实预算占用。单独的 Ready 标记在 owner 退出后仍可能留存；单独的 Task terminal outcome 也不证明整个执行子树已 reap。取消若在执行准备记录建立前释放容量，准备线程可能随后创建容器。N2 Manager 在保存失败前已经修改内存，不能以其内存终态确认清理成功。

## 解决方案

私有 acceptance envelope v2 将 ledger、预算与预留一并原子发布。保留 public ledger 和接受合同不可变；该 envelope 的 runtime-held 状态合法变化，因此验证应比较全部不变事实并单独核对经过证明的释放，而非要求整个私有文件永远相同。

每次新接受、准备、启动与 GC 在原 acceptance.lock 内要求活固定 inode 的 capacity owner 和原执行 owner；无主执行或 PendingVerification 保留占用。Logs.create 与取得其 owner lease 在真实容量校验的同一锁内完成，先于输入准备。释放由私有不可构造的原 executor/reap 证明派生，与事件序号和镜像指纹绑定；磁盘占用在实际保留文件清理前继续记账。

daemon 的显式 config-folder 统一 N2/Task/token 默认根；共享已有 Manager。绑定前核实真实主体、Use、容量、Session 和同根持久 Plan。确认取消先保存 cleanup intent，再经原 Manager close；保存失败保留 intent、重载原 Manager、核实持久 Disposed 后幂等重试。Session 孤儿 Failed 不推断 Task 失败。

## 预防措施

- Ready 不能只有持久 bool 或 PID；检查原 inode 和非阻塞 flock，避免反向锁序死锁。
- 授权 callback 保持在 start.lock 外，保留重入取消；真实容量在最终 StartIntent 临界区内部重查。
- std File::lock 的稳定版本晚于项目 Rust 1.85；复用现有 Linux flock 适配，避免新增 unsafe 或抬升 MSRV。
- 显式 config-folder 与 compatibility serve 分别选择入口根；后者复用 CLI 的 node_dir（NEXUS_CONFIG_DIR / XDG / HOME），不能把默认 token 根改为 /etc/nexus。回归测试移除配置/token 覆盖变量，实际启动子进程并用用户目录 token 查询 N2。
- 内部 E3 和有限 daemon E4 不代替完整 Submit/下载/Windows E5；旧场景期待继续保留。

## 参考

- docs/N3-8-CAPACITY-SESSION-CONTRACT.md
- .evidence/n3-8/spec-freeze.json
