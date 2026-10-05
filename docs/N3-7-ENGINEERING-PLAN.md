# N3-7 工程门禁稳定批

基线：`7933f1cf0661010ad65234dbf494957388820df6`；规划日期：2026-10-05（Asia/Shanghai）。
任务类型 bugfix，修正已有工程流程；保持现有 Product、MODULE、Scenario、Policy、Cargo 契约。
334 个既有受保护文件摘要在 `.evidence/n3-7/freeze.json`。

## 目标与范围

1. 正常 Git hooks 在 linked worktree 使用该 worktree 的目标、配置与当前 Harness；
   清除 Git 导出的仓库本地环境，保持当前目录与真正的 index/HEAD。
   保留所有既有门禁、STALE 和独立 Review 检查；安装与运行不落盘凭据。
2. Harness 在相关真实 CLI 测试前构建当前 CLI/daemon，不在测试内部嵌套 Cargo。
   使用 Cargo metadata 的真实 test target，不把 tests 下的 helper.rs/mod.rs 当 target。
   构建失败为可诊断门禁失败；不得选择旧 master 二进制或伪造通过。
3. 网络轨只做有界诊断：fabric basic 最多三个固定观测，N1 检查可运行前置与已有退出路径。
   保存原始 stdout/stderr/exit、工具和源码摘要；不修改原场景期望。
   本批不进行 sudo/setcap、主机路由/物理接口/IP/TUN 修改；真实网络环境不足单独记录。
4. 集成验证发现既有 N2 plan explain 单元测试依赖宿主配置，使用存在的静态
   dev-svc 种子却断言不存在资源的 exit1。最小修复限定 apps/nexus/src/plan_cli.rs
   的 cfg(test)：注入私有目录，保留明确不存在资源的 exit1/NOT_FOUND 断言，
   分别验证真实估算的非承诺字段。产品实现/API、Scenario、334冻结文件保持原字节。
   R1仅对应修复前源；新源重新 Fast 并由不同执行者做 R2，之后运行 Full。
   首轮 Full 又捕获 N2 idle-client 空目录并发身份初始化导致握手失败；
   16并发冷初始化回归在旧 ensure_auth_identity 上得到明确FAIL，修复同进程
   首次创建的单 writer/二次读取，保留已存身份无锁读取和原 idle-client 测试。
   不声明跨进程同时初始化已修复；由节点所有者协调。新源经不同执行者R3后 Full。
   归档 basic 的 packets 输出与当前
   stream verifier 不符；旧三个观测仅保留为旧 binary 数据，不能证明当前场景通过。
5. 保持 N3 Submit/完整下载原能力边界；后续 N3-8～12 不在本批启动。

## 并行所有权

| 轨道 | worktree / 分支 | 文件与职责 |
|---|---|---|
| A hooks | /workspace/ws-n3-7-hooks / n3-7/hooks | .githooks 脚本、安装与说明、钩子回归探针 |
| B Harness | /workspace/ws-n3-7-harness / n3-7/harness | engineering/nexus-harness/src，当前 binary 预构建与 metadata target 发现及回归 |
| C 网络诊断 | /workspace/ws-n3-7-network / n3-7/network | 只读业务源；仅 .evidence/n3-7 下 raw 和诊断报告 |
| 集成 | /workspace/ws-n3-7-integration / n3-7/integration | 本计划、知识沉淀、N2 非隔离测试与冷身份初始化 bugfix、SHA 核对、集成验证与独立 review |

独立 target / NEXUS_AGENT / token / config / runtime / evidence，Rust1.98.1、jobs2、
debug0、incremental0。source `.evidence/n3-7/activate.sh` 后执行本 worktree 工具。
334冻结文件不得改变；不增加依赖或架构边；生产代码由既有 Owner 处理。
工作区原 master、各旧批次源码/分支/evidence 保留。清理仅针对已完成 target 缓存，
上批关键可执行文件已归档并记录SHA；不共享并发 Cargo target。

## 验收与证据

- 保留已知 GIT_DIR 污染的六项 Harness 单元测试红灯以及清除后的40项通过证据。
- 新钩子回归覆盖 linked worktree、继承旧 master target/PATH、Git local env、安装范围、
  正常拒绝（Fast FAIL、缺Review或STALE）和真实门禁执行。
- Harness 回归覆盖 clean/missing/source-stale binary 的正确构建、显式失败及真实 CLI 链；
  Cargo metadata 测试发现包含不同目标名和 nested helpers，杜绝不存在的 --test mod。
- 所有假工具/小型 fixture 明确标为工程单元夹具；最终实际工程门禁与真实产品进程另外验证。
- 每轨交付diff/patch、逐文件SHA、334冻结核对、原始验证命令与退出码、限制和交付说明。
- 集成：check → affected → Fast → 独立八维Review（最多3轮）→ Full。
  review/full期间源冻结，原生统计包含全部product/platform/engineering/regression。
- Full 网络失败或环境缺失据实保留；N3缺完整verifier的UNKNOWN不代表产品完成。
  本批交付不自动提交或推送新改动；后续以用户指令执行。
