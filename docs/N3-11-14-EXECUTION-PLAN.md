# N3-11 至 N3-14 执行计划

本计划记录开发顺序与验收边界，不替代 PRODUCT、MODULE 或各批冻结契约。进度更新：2026-10-19；当前 N3-12 工作基线为 a97cfc0。本地验证使用 Rust 1.98.1；真实 xc-pc-linux Full 和 Windows 请求方双机证据待补。

## 当前进度

N3-11 初始化、只读检查与普通 daemon 接线已提交至 37e0cff，Draft PR #18：https://github.com/medivhc/nexus-fabric/pull/18 。2026-10-16 查询仍为 OPEN、Draft，未合并。历史组件有限 E4、Fast 和独立第三轮 review 通过；此前“27 项”计数有误，当前真实二进制回归文件/ELF 为 23 项，2026-10-17 直接执行为 23 PASS。历史工具验证不能当作当前工具链的最终组合验证、真机 Full 或完整 N3 Submit 验收。

master 新增 WebRTC ICE 绑定修复及 sshd 依赖显式 skip 边界，N3-11 已 rebase；旧基线 gateway FAIL 证据不证明修复后的失败状态，不复用旧输入结论。

N3-12 在独立 task/n312-contract worktree 基于 PR #18 继续，正式契约、requester Workspace fixture 与产品场景 RED 已冻结。各组件分别以独立测试评审 APPROVED 为实现前置门禁，当前进度为：

- 有界 freeze 与 Linux 原子 no-replace 发布已提交 a97cfc0，相关 124 项测试、Fast 与独立代码评审通过。
- Rust DTO 的测试评审与代码评审均 APPROVED；87 项新增测试加 12 项原测试通过，Fast 与 WASI 检查通过；实现已集成至协调工作区，尚未提交。
- CLI/真实二进制边界测试 R8 APPROVED，已冻结；CLI 修复最终响应等待期间的 bundle 篡改缺口后，check、affected、Fast 及独立代码评审 R2 均通过，六文件实现已集成。daemon 接线与真实后端已汇合；最终组合按标准门禁、完整 E4 与独立代码评审验收。
- 提供方持久事务测试 R11 独立评审 APPROVED，120 个测试入口已冻结。真实后端与安全 IO 已实现，局部验证为 113 passed / 0 failed / 7 helper ignored，子进程流程由实际 wrapper 执行；冻结断言保持原样。后端与 daemon 已汇合至协调工作区，整体验收以最终源码组合的标准门禁、完整 E4 和独立代码评审证据为准。

2026-10-19 验收更新：当前工作区真实 release ELF 的 N3-12 有限 E4、N3-11 有限 E4 与协议适配器 71 个子用例均通过。原 51 方法二进制套件整体 FAIL 保留：50 方法通过，协议方法的 HTTP/1.0 fixture 前置错误已作独立等价审计并修正为正式 HTTP/1.1；随后只重跑该方法通过，不能写成 51 方法单次全通过。

环境默认 PATH 曾选中主仓库的旧 Harness；旧工具 PASS 只保留为历史观察。已从当前工作区构建并改用绝对路径的当前 Harness：check 4/4 PASS，affected 因私有短期租约报忙 FAIL，Fast/独立组合 review/Full 尚未通过。受控 trace 已确认无关子进程继承 FD 会延长 close-only flock；原失败的精确 scope 阶段因无 trace 仍 UNKNOWN。新租约生命周期回归测试已编译，3 个确定性 RED、4 个控制 PASS，等待独立测试评审后修复，原 N3-12 冻结用例不变。

N3-13 仅在独立 worktree 形成 DRAFT，未运行 RED、未冻结或实现。独立契约检查和传输静态审计要求先明确运行中撤权、双端 Session 归属、交接/GC 预算以及 Fabric 完整背压/生命周期界限；不能把配置候选或 Docker 可连接写成能力已验收。

## 批次与依赖

| 批次 | 用户可观察交付 | 关键约束 | 验收 |
|---|---|---|---|
| N3-11 | 正式提供方 init/check；正常 daemon 恢复 | 固定身份、原容量权威、可证明的初始化中断恢复、check 零写入、完成后幂等 | 新增有限 E4、真实 binary E3、受影响测试、独立审查；不宣称完整 Submit |
| N3-12 | 固定 Commit 的 Snapshot staging、分片上传与恢复 | 独立接受前预算与 durable receipt、授权作用域、manifest/blob 校验、GC roots、重复与中断不丢原输入 | 先冻结入口和 wire 契约，在旧 binary 取得 RED；本机真实 CLI E4与故障测试 |
| N3-13 | 经保密双向认证通道提交并执行，取得日志与产物 | peer identity 绑定、实际 grant、真实容量与唯一 SessionManager、原执行 owner、幂等与 StartIntent 恢复 | 接通原完整 N3 场景 verifier；两个独立进程 E4、真实隔离执行、回归与独立审查 |
| N3-14 | Windows 请求方接入 Linux 提供方 | 平台路径/原子落盘/凭据语义、真实双机环境与 Engine digest、完整性与断线恢复 | 全部冻结 N3 E4、新鲜 Full、Windows→Linux E5；证据不足明确保留缺口 |

N3-12 的范围已冻结为 Linux 本机 numeric loopback/Unix 上传。远端上传与提交需要 N3-13 的实际保密双向认证适配；不能通过传入 principal 字符串或放宽 LocalAPI 地址完成认证。N2 明文 admission 也不能替代该通道。Windows 请求方属于 N3-14。

本批 E4 的 strace 过滤会设置 NoNewPrivs，仅用于已核查的非特权暂存进程；不能代替 N3-13 的 Engine 或特权执行资格验证。

每批依次执行 Contract → 旧实现 RED → 冻结 → 编写可编译 RED 测试 → 独立盲评测试/冻结 → 实现 → Check/affected/Fast → 独立八维 review/修复 → 完整适用验证。实现者不修改冻结 expectations 使实现变绿。协调者串行集成，执行者独立分支、worktree、target 与 evidence 命名空间；不直接推送 master。

## 待解决的验收条件

- 在更新后的 master 上重测真实 WebRTC 场景，历史旧基线 FAIL 保留为历史证据；缺 sshd 的显式 skip 不代替安装了依赖的真实场景通过。
- 为 N3-13 的真实执行确认受支持 Engine、环境镜像与实际资源隔离能力；Docker daemon 可连接不等于执行环境已通过 qualification。
- 为 N3-14 获得实际 Windows 与 Linux 两机连接信息和授权测试环境；两个本机进程只属于 E4。
- 新鲜证据必须绑定当前 revision、dirty state、配置与工具链。历史 PASS 不能替代当前完整验证，未完成条件不能写为 Final PASS。
