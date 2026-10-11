---
id: resource-quota-audit-gate-001
title: 全门禁绿 + 74 个测试通过仍漏掉"单会话打挂节点"——高风险网络/文件变更必须先做资源核算
tags: [process, review, resource-accounting, fd-limit, rss, dos, mutation-testing]
module: engineering / nexus-web-gateway
severity: high
source: review
date: 2026-10-11
related: ["panic-abort-external-arith-001", "send-queue-hol-block-001", "ice-candidate-bind-set-001"]
---

## 问题描述

一次网关文件模块变更的**自验全绿**：`cargo fmt --check` 0、`--lib` **46 passed**、
`--test gateway_e2e` **28 passed**、`clippy --all-targets` 0 warning（workspace `warnings = deny`）、
`nexus-harness verify --fast` **9 门全 PASS**、活体网关起得来、真实 sshd SFTP 用例在跑。

18 角度独立评审仍然给出 **16 FAIL**，其中"单会话即可打挂节点"四项全部在上述绿灯下不可见：

| 病灶 | 实测 |
|---|---|
| 每个下载分片 `fileStreamSeq++` 新 stream_id，后端按 stream_id 缓存 `File::open` 句柄、只在会话 `release()` 清 | **第 1022 片 EMFILE**（宿主 `ulimit -n 1024`）；此后同节点 `file_list` 报 os error 24、新浏览器 WSS 连接 125 µs 失败、裸 TCP connect 1.8 µs 失败 ⇒ **一个令牌用户下载 63.8 MiB 就锁死节点前门** |
| `max_upload_bytes` 校验的是本片 end 偏移，不是"连续前缀 + buffered 总量"；乱序缓冲无字节上限 | 8 条流灌乱序片 ⇒ **RSS +1028 MiB** |
| 发送队列无界 + 超大 ack 反复克隆 | RSS +182.8 MB / 10 次观测 |
| `last_activity` 被任意命令/回执刷新 | idle=3 s 下每 1.5 s 一次 `file_stat`，**15 s 内 0 次回收** ⇒ 会话与内存永久保留（"滴灌保活"） |

同批被证实的还有：令牌防线零节流（单会话 **5000 次错 token 全被处理**、~74/s、无锁定），
以及 SFTP 每会话新建握手（**84 次认证/秒**可把目标账号打进 faillock）。

## 根因分析

不是"测试不够多"，是**测试维度里没有资源这个轴**：46/28 个用例断言的是功能与错误语义，
没有一个断言"这个路径消耗多少 fd / 多少字节 / 多少线程 / 消息多大"。`verify --fast` 的门禁
是编译/格式/clippy/架构策略/依赖治理一类，同样不计算资源。

第二个根因是**装饰区不知道自己在哪**：评审用变异测试列出"改坏仍绿"的清单
（`unknown upload stream`/`unknown file session` 应答、SFTP `remote_path` 绕过 `normalize_rel`
即 **G13 在 SFTP 侧零测试**、空洞检查/重放容错的 e2e 层、file 空闲超时——所有测试写死
`idle_timeout_secs: 600`、入站 `chunk_bytes` 上限、SFTP `./..` 过滤）。llvm-cov 显示 `file.rs`
1231 行未覆盖 116，**未覆盖处集中在安全/错误路径**。覆盖率数字看着健康，危险路径全黑。

## 解决方案

把"配额与资源核算"升级为高风险变更（网络/文件/会话类）在**独立 Review 之前**必做的一步，
产出两份输入交给 Reviewer：

1. **上界推导**（V2 §2/§6 即模板，用真实数字，不写"应该没问题"）：
   - fd：单浏览器会话最坏 = WSS(1) + 文件会话 4 ×（读句柄 8 + 上传 part ≤2 + SFTP socket 1 +
     事件管道 2）≤ **53**；全局 32 会话 ⇒ 文件面 ≤ **416**，对宿主 `ulimit -n 1024` 留 ≥512 余量；
     实现用**登记式 fd 计数**（open/close 唯一入口），预算耗尽先拒后开。
   - RSS：worker 栈 2 MiB + 读缓冲 ≤ chunk_bytes + 排队 ≤4 MiB + 乱序缓冲 ≤4 MiB + ssh2 ≈0.5 MiB
     ⇒ 每会话 **≤ ~11 MiB**，全局 ≈352 MiB。
   - 消息大小：单条 JSON 硬上限 64 KiB（构造性上界，见 `send-queue-hol-block-001`）。
   - 配额表齐全：会话数/句柄数/流数/缓冲字节/队列字节/页条目/空闲超时/握手速率，
     每项给默认值 + `validate()` fail-closed（对齐仓库既有 `SshConfig.max_terminals` 纪律：0 即拒启动）。
2. **"改坏必须红"的变异清单**写进 Review 输入，逐条列名（`stat→lstat`、`checked_add→+`、
   `create_new→create`、移除 `O_NOFOLLOW`、`req_id` 错配、`hard_link→rename`、放宽 idle 刷新语义、
   移除 capability 门控……），同时把已知**装饰区**如实列出，让 Reviewer 不必重新发现。

配套的资源核算测试（V2 §10）：fd 计数器断言峰值 ≤ `max_read_handles` 并用 `/proc/self/fd` 交叉验证；
`/proc/self/statm` 前后差 < 每会话预算；10 万条目 + 恶意长文件名下**每条** ack ≤64 KiB；
灌满文件类队列预算断言 ssh 消息零丢失。

## 预防措施

- 新条目/新模块只要触碰 **fd、内存、消息大小、线程数、握手/认证速率**，Review 前自问：
  "单会话最坏占用是多少？乘上会话上限还低于宿主 rlimit 吗？谁负责回收？"——答不出就是还没设计完。
- 空闲回收语义要区分"改变资源占用的命令"与"只读探针"；只读探针不得无限续命（否则滴灌即永久持有）。
- 认证/握手类入口默认要有失败节流与速率上限（`auth_fail_limit/window/lockout`、令牌桶 + 熔断），
  并意识到"每会话新建到第三方服务的连接"是**对他人的 DoS**，不只是自己的开销。
- 测试写死宽松上限（`idle_timeout_secs: 600`）= 该路径零覆盖；超时类测试用 1-3 s 配置并断言回收事件。
- 变异测试（或至少人工"改坏一次看红不红"）应作为高风险模块 Review 的常规取证手段；
  覆盖率百分比不能替代它。
- 案卷诚实度：不要用"测试通过数"充当资源安全性证据（本案例的 46/28 全部属实且全部无害）。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` §1 角度 5/9、P0-2/P0-5/P0-6、§4 装饰区、§5 更正
- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §2（全绿门禁矩阵）
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §2（上界推导）、§6（配额表）、§10（测试策略）
