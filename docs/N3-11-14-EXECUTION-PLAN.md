# N3-11 至 N3-14 执行计划

本计划记录开发顺序与验收边界，不替代 PRODUCT、MODULE 或各批冻结契约。核实日期：2026-10-11；远端 master 基线 d50d8fe。执行环境已恢复，Rust 1.98.1 与 Linux 本地 Docker 可用；未获得真实 Windows 请求方测试机证据。

## 当前进度

N3-11 契约已在旧真实 nexusd 上取得 RED：正式 `task-provider init` 返回 exit2，`product.n3-11-provider-init` 为 FAIL。契约提交 ecf4cb5，冻结清单位于 `.evidence/n3-11/freeze.json`。初始化后端、CLI/启动接线与独立二进制测试分别在隔离 worktree 实现，尚未产生本批 GREEN 或完整实现验收结论。

基线两处纯 rustfmt 修正已独立审查并提交 33e82ad；该 clean revision 的 Fast 为 PASS。修改前的 master 也复现 WebRTC 控制通道连接失败，完整 gateway E2E 为 7 PASS / 13 FAIL；不能将 clean Fast 中“无受影响测试”解释为这些 E2E 已通过。当前 loopback UDP 实测可收发，WebRTC 故障根因仍待定位。

## 批次与依赖

| 批次 | 用户可观察交付 | 关键约束 | 验收 |
|---|---|---|---|
| N3-11 | 正式提供方 init/check；正常 daemon 恢复 | 固定身份、原容量权威、可证明的初始化中断恢复、check 零写入、完成后幂等 | 新增有限 E4、真实 binary E3、受影响测试、独立审查；不宣称完整 Submit |
| N3-12 | 固定 Commit 的 Snapshot staging、分片上传与恢复 | 独立接受前预算与 durable receipt、授权作用域、manifest/blob 校验、GC roots、重复与中断不丢原输入 | 先冻结入口和 wire 契约，在旧 binary 取得 RED；本机真实 CLI E4与故障测试 |
| N3-13 | 经保密双向认证通道提交并执行，取得日志与产物 | peer identity 绑定、实际 grant、真实容量与唯一 SessionManager、原执行 owner、幂等与 StartIntent 恢复 | 接通原完整 N3 场景 verifier；两个独立进程 E4、真实隔离执行、回归与独立审查 |
| N3-14 | Windows 请求方接入 Linux 提供方 | 平台路径/原子落盘/凭据语义、真实双机环境与 Engine digest、完整性与断线恢复 | 全部冻结 N3 E4、新鲜 Full、Windows→Linux E5；证据不足明确保留缺口 |

N3-12 的安全最小范围暂定本机 loopback/Unix 上传。远端上传与提交需要 N3-13 的实际保密双向认证适配；不能通过传入 principal 字符串或放宽 LocalAPI 地址完成认证。N2 明文 admission 也不能替代该通道。此范围将在 N3-12 契约阶段明确冻结，当前仅为设计提案。

每批依次执行 Contract → 旧实现 RED → 冻结 → 实现 → Check/affected/Fast → 独立八维 review/修复 → 完整适用验证。实现者不修改冻结 expectations 使实现变绿。协调者串行集成，执行者独立分支、worktree、target 与 evidence 命名空间；不直接推送 master。

## 待解决的验收条件

- 定位并修复或在可用真实环境中核实 WebRTC 基线故障，保留当前 FAIL 证据。
- 为 N3-13 的真实执行确认受支持 Engine、环境镜像与实际资源隔离能力；Docker daemon 可连接不等于执行环境已通过 qualification。
- 为 N3-14 获得实际 Windows 与 Linux 两机连接信息和授权测试环境；两个本机进程只属于 E4。
- 新鲜证据必须绑定当前 revision、dirty state、配置与工具链。历史 PASS 不能替代当前完整验证，未完成条件不能写为 Final PASS。
