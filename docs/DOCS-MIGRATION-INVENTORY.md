# 文档迁移只读清单（DOCS-MIGRATION-INVENTORY）

> **性质声明：本文件仅为供人工裁决的迁移清单，未移动、未修改、未删除任何现有文件。**
> 分支 `workbuddy/docs-migration-inventory` 相对 master 的唯一变更即新增本文件。

## 0. 枚举口径与元信息

| 项 | 值 |
|---|---|
| 仓库 | `medivhc/nexus-fabric`（GitHub） |
| 分支 | `master`（HEAD `c04b409458370bd20e08adfa9c1d06d8910c26cd`） |
| 枚举方法 | 下载 master tarball（codeload）全量解包后 `find . -name '*.md' -type f`；与 `git clone --depth 1` 工作树逐文件 sha256 抽验一致 |
| **枚举 .md 总数** | **290** |
| 清单条数 | **290**（与枚举总数一致，逐文件一条） |
| 枚举时间 | 2026-10-25 |

说明：任务背景中「约 278 个」为约数；本次实际枚举 **290** 个 .md（含隐藏目录 `.agents`/`.evidence`/`.grill`/`.pee`/`.githooks` 内的文档）。仓库内 `docs/DOC-AUDIT-2026-10-06.md` 记录的「276 个」为 2026-10-06 时点快照，此后新增 recovery/、web-gateway docs 等文件，口径已变化（见冲突项 C5）。

## 1. 分类规则

| 类别 | 判定标准 |
|---|---|
| baseline（基线） | 文件自我声明或被仓库声明为「基线」（Final Design Baseline / 产品定义基线 / 技术设计基线），优先级高于仓内非契约描述 |
| contract（契约） | 标题/文件名/正文自我声明为契约（Contract）、冻结（FROZEN 带 contract hash）或作为 harness 机器契约被消费的规范文档 |
| current（现行） | 现行有效、人与 Agent 日常依赖的门面、状态、设计与参考文档（含机器生成的当前状态报告） |
| 代码内嵌文档 | 位于代码/工程目录（`crates/`、`apps/`、`benches/`、`fuzz/`、`tests/`、`scenarios/`、`.githooks/`、`engineering/`、`.agents/skills/`）内，随代码与工程体系维护的 README / MODULE / SKILL 等模块文档 |
| archive（归档） | 历史快照、已完成批次的计划/实现记录、决策记录、知识条目、评审/审计报告、STALE/superseded 文档、恢复归档 |

建议去向即四层目标目录：`baselines/` / `current/` / `contracts/` / `archive/`；代码内嵌文档一律「保留原地」。

## 2. 逐文件迁移清单（290 条）

### 2.1 baseline（基线）（4 份）

| # | 路径 | 判定理由 | 建议去向 |
|---|---|---|---|
| 1 | `Nexus_Unified_System_Design_Specification_v9.md` | 根级存放的 v9 规范副本，自称 Final Design Baseline，与 docs/baselines/v9-design-spec.md 内容重复（见冲突项 C1） | baselines/（与 baselines/v9-design-spec.md 去重后保留其一） |
| 2 | `docs/baselines/README.md` | 基线目录索引，自我声明两份外部基线为产品/设计真相来源、优先级高于仓内非契约描述 | baselines/ |
| 3 | `docs/baselines/v9-design-spec.md` | 文件头自我声明 Final Design Baseline 的技术设计基线（v9 统一系统设计规范） | baselines/ |
| 4 | `docs/baselines/whitepaper-v1.0-product.md` | 文件头自我声明 v1.0 产品定义与交付基线（产品白皮书） | baselines/ |

### 2.2 contract（契约）（17 份）

| # | 路径 | 判定理由 | 建议去向 |
|---|---|---|---|
| 1 | `ARCHITECTURE.md` | 标题即 Nexus Architecture Contract；harness.toml [paths].architecture/[protection]/[hooks.protected] 机器消费的架构契约 | contracts/（移动需同步 harness.toml 与 crate 注释引用） |
| 2 | `CONTRACT-scenario-pack.md` | 文件名与正文均自我声明为场景包机器接口冻结契约（字段名不可更改），被 harness scenario.rs/scenario_cmd.rs 引用 | contracts/（不可轻移） |
| 3 | `DEVELOPMENT.md` | 标题即 Nexus Development Contract；harness.toml [paths].development 机器消费的开发契约 | contracts/（移动需同步 harness.toml 引用） |
| 4 | `PRODUCT.md` | 标题即 Nexus Product Contract；harness.toml [paths].product/[protection]/[hooks.protected] 机器消费的产品契约 | contracts/（移动需同步 harness.toml 与全部 scenarios requirement 引用） |
| 5 | `docs/N3-10-OPERATOR-GRANT-CONTRACT.md` | N3-10 本地提供方 scoped Use grant 运维契约 | contracts/ |
| 6 | `docs/N3-11-PROVIDER-INIT-CONTRACT.md` | N3-11 正式提供方初始化与只读检查契约（状态：契约冻结） | contracts/ |
| 7 | `docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md` | N3-12 快照冻结与有界 staging 契约（与场景/metadata 共同冻结） | contracts/ |
| 8 | `docs/N3-13-REMOTE-TASK-CONTRACT.md` | N3-13 远端固定输入 Task 接线契约草案（DRAFT/未冻结/未运行 RED） | contracts/ |
| 9 | `docs/N3-13A-BOUNDED-MTLS-CONTRACT-DRAFT.md` | N3-13A 有界 mTLS 传输与 peer context 分片草案（candidate/pending） | contracts/ |
| 10 | `docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md` | N3-6 本地提供方服务与双向 TLS 前置契约 | contracts/ |
| 11 | `docs/N3-8-CAPACITY-SESSION-CONTRACT.md` | N3-8 容量与既有 Session 所有权契约 | contracts/ |
| 12 | `docs/N3-9-ARTIFACT-CLI-CONTRACT.md` | N3-9 真实 Artifact CLI 下载契约 | contracts/ |
| 13 | `docs/N3-MODEL-CONTRACT.md` | N3 首期模型与契约（Contract-First 阶段 A 产物） | contracts/ |
| 14 | `docs/e2e-test-system-contract.md` | E2E 测试系统契约（场景 schema 与 evidence 绑定契约），被 harness commands.rs/scenario.rs 与 test-plan 引用 | contracts/（不可轻移） |
| 15 | `docs/foundation/NAT-TRAVERSAL-CONTRACT.md` | v1.1 FROZEN 冻结合同（带 contract hash，实现轨道不得修改），被 nexus-nat-traversal/src/lib.rs 引用 | contracts/（不可轻移） |
| 16 | `docs/foundation/NAT-TRAVERSAL-STALE.md` | 冻结合同配套的旧证据 STALE 唯一登记表（v1.1 要求 gap-first 重跑的依据） | contracts/（与冻结合同同层维护） |
| 17 | `engineering/plugins/plugin-contract.md` | Harness 插件最小输出契约（合法 status 枚举） | contracts/ |

### 2.3 current（现行）（29 份）

| # | 路径 | 判定理由 | 建议去向 |
|---|---|---|---|
| 1 | `AGENTS.md` | 工程制度总纲（Agent-Native Engineering System），被 CI/harness/同步脚本多处引用 | current/（不可轻移） |
| 2 | `CONTRIBUTING.md` | 贡献指南（commit 类型/范围规范），被 commitlint workflow 引用 | current/（不可轻移） |
| 3 | `DEV-ENV.md` | 远程 Linux 开发环境文档，被 rust-toolchain.toml/devcontainer/CI 引用 | current/（不可轻移） |
| 4 | `FILE_MANIFEST.md` | 仓库文件清单导航层（L4），持续登记维护并带历史漂移修补记录 | current/ |
| 5 | `README.md` | 仓库门面入口，概述 Resource Fabric 与 Agent-Native 工程系统全貌 | current/ |
| 6 | `docs/CODE-INTELLIGENCE-KNOWN-ISSUES.md` | frontmatter status: current 的 Code Intelligence 已知问题清单（自称非契约） | current/ |
| 7 | `docs/DAEMON_ARCHITECTURE.md` | daemon 架构设计（状态：已实现），被 nexusd 装配/配置代码与产品场景引用 | current/（不可轻移） |
| 8 | `docs/DEVELOPMENT-PROCESS.md` | 实际执行中的开发流程（tribal knowledge），自称与 AGENTS.md/DEVELOPMENT.md 制度互补 | current/ |
| 9 | `docs/DOCUMENTATION-ARCHITECTURE.md` | 文档架构设计（L1-L4 分层 + frontmatter 保鲜元数据），现行有效的文档体系规约 | current/ |
| 10 | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md` | frontmatter status: current 的 N3 功能与代码恢复总结（能力边界说明） | current/ |
| 11 | `docs/PROJECT-STATUS.md` | frontmatter status: current 的项目状态页（verified-against b9ae124） | current/ |
| 12 | `docs/USER_MANUAL.md` | 仓库级用户手册（2026-10-04/05 按代码实现对齐，附退出码三档语义） | current/ |
| 13 | `docs/WINDOWS_TUN_DESIGN.md` | Windows TUN 详细设计（基于真机验证的三种运行模式），被 daemon config.rs 与 win 场景引用 | current/（不可轻移） |
| 14 | `docs/foundation/DESIGN.md` | N1 地基设计（状态：讨论稿，核心分层已对齐、§11 待决策），被 discovery/projection/nexusd 代码与约 30 个场景 requirement 引用 | current/（不可轻移） |
| 15 | `docs/foundation/NAT-TRAVERSAL-DESIGN.md` | NAT 穿透设计 v0.1（D1-D6 已拍板、可进合同阶段），冻结合同的设计基线 | current/ |
| 16 | `docs/product/product-document.md` | 按 HEAD ced3b7a 源码函数体实证的产品文档（可用/已实现未验证/占位三级证据分级） | current/（与 PRODUCT.md、白皮书的冲突见冲突项 C3） |
| 17 | `docs/product/user-manual.md` | 按 HEAD ced3b7a 源码实证的用户手册（每条结论带文件:行号） | current/（与 docs/USER_MANUAL.md 双源冲突见冲突项 C2） |
| 18 | `docs/protocols/AVAILABILITY.md` | 协议可用性状态汇总页（数据源为 interop/MATRIX.md 的互操作验证结论） | current/ |
| 19 | `docs/protocols/anytls.md` | AnyTLS 协议语义文档（clean-room 参考），被 nexus-outbound-anytls/src/lib.rs 引用 | current/（不可轻移） |
| 20 | `docs/protocols/bootstrap-join/03-design-v2-final.md` | Bootstrap 自动入网 v2 修订定稿（逐条落实评审 7 个阻断项，实现以此为准） | current/ |
| 21 | `docs/protocols/bootstrap-join/README.md` | bootstrap-join 设计文档集索引（声明实现与验收一律以 v2 定稿为准） | current/ |
| 22 | `docs/protocols/hysteria2.md` | Hysteria2 协议语义文档（clean-room 参考），被 nexus-outbound-hysteria2/src/lib.rs 引用 | current/（不可轻移） |
| 23 | `docs/protocols/interop/MATRIX.md` | 出站协议互操作证据总表（recompute-verdicts.py 机械生成、人工零编辑的唯一正本） | current/（不可轻移，机器生成物） |
| 24 | `docs/protocols/interop/NEXT-STEPS.md` | 互操作修复路线（人工维护，排修复顺序/依赖/复验口径，不改变 verdict） | current/（不可轻移） |
| 25 | `docs/protocols/vless.md` | VLESS 协议语义文档（clean-room 参考），被 nexus-outbound-vless/src/lib.rs 引用 | current/（不可轻移） |
| 26 | `engineering/TRACING.md` | tracing 体系设计（span/event 插桩与导出中立原则），现行有效的横切设计 | current/ |
| 27 | `engineering/e2e/acceptance_todo.md` | E2E 验收 Todo（_render_coverage.py 生成的现行无覆盖锚点清单） | current/（生成物，不可轻移） |
| 28 | `engineering/e2e/coverage_audit.md` | E2E 覆盖审计报告（277 场景 × 97 PRODUCT 锚点，修复后口径） | current/（不可轻移） |
| 29 | `engineering/e2e/coverage_matrix.md` | E2E 覆盖矩阵（_render_coverage.py 生成的锚点×场景矩阵） | current/（生成物，不可轻移） |

### 2.4 代码内嵌文档（86 份）

| # | 路径 | 判定理由 | 建议去向 |
|---|---|---|---|
| 1 | `.agents/skills/README.md` | 项目级技能索引，harness.toml [skills].index 直接指定 | 保留原地（不可轻移） |
| 2 | `.agents/skills/nexus-contract-first/SKILL.md` | nexus-contract-first 技能本体（契约阶段流程），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 3 | `.agents/skills/nexus-evidence/SKILL.md` | nexus-evidence 技能本体（证据生成与解读），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 4 | `.agents/skills/nexus-knowledge/SKILL.md` | nexus-knowledge 技能本体（知识库检索/沉淀），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 5 | `.agents/skills/nexus-multiagent/SKILL.md` | nexus-multiagent 技能本体（多 Agent 编排），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 6 | `.agents/skills/nexus-review/SKILL.md` | nexus-review 技能本体（独立代码审查），被 recovery printed-path-coverage.json 引用 | 保留原地（不可轻移） |
| 7 | `.agents/skills/nexus-selfrepair/SKILL.md` | nexus-selfrepair 技能本体（有界自修复循环），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 8 | `.agents/skills/nexus-task/SKILL.md` | nexus-task 技能本体（端到端工程任务流程），harness.toml [skills].entries 列出 | 保留原地（不可轻移） |
| 9 | `.agents/skills/nexus-test-review/SKILL.md` | nexus-test-review 技能本体（TDD 测试盲评），被 red-evidence txt 与 recovery manifest 引用 | 保留原地（不可轻移） |
| 10 | `.githooks/README.md` | .githooks 目录说明（harness.toml [hooks] 指向该目录安装门禁） | 保留原地 |
| 11 | `apps/nexus-platform-host/MODULE.md` | apps/nexus-platform-host 能力转 dump 二进制模块契约 | 保留原地 |
| 12 | `apps/nexus/MODULE.md` | apps/nexus crate 模块契约，harness.toml [discovery].module_contract 以 MODULE.md 发现的模块文档 | 保留原地 |
| 13 | `apps/nexusd/MODULE.md` | apps/nexusd crate 模块契约（D1-D6 冻结契约被 dataplane.rs 引用） | 保留原地 |
| 14 | `benches/README.md` | benches 目录说明（基准测试组织） | 保留原地 |
| 15 | `crates/nexus-auth/MODULE.md` | crates/nexus-auth crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 16 | `crates/nexus-compute/MODULE.md` | crates/nexus-compute crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 17 | `crates/nexus-connectivity/MODULE.md` | crates/nexus-connectivity crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 18 | `crates/nexus-control-api/MODULE.md` | crates/nexus-control-api crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 19 | `crates/nexus-delivery/MODULE.md` | crates/nexus-delivery crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 20 | `crates/nexus-diagnostics/MODULE.md` | crates/nexus-diagnostics crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 21 | `crates/nexus-discovery/MODULE.md` | crates/nexus-discovery crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 22 | `crates/nexus-dns/MODULE.md` | crates/nexus-dns crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 23 | `crates/nexus-domain/MODULE.md` | crates/nexus-domain crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 24 | `crates/nexus-fabric/MODULE.md` | crates/nexus-fabric crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 25 | `crates/nexus-flow-session/MODULE.md` | crates/nexus-flow-session crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 26 | `crates/nexus-ingress/MODULE.md` | crates/nexus-ingress crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 27 | `crates/nexus-measurement/MODULE.md` | crates/nexus-measurement crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 28 | `crates/nexus-nat-quality/INTERFACE-TRACK1.md` | nexus-nat-quality crate 内接口跟踪文档（Track1 接口面） | 保留原地 |
| 29 | `crates/nexus-nat-quality/MODULE.md` | nexus-nat-quality crate 模块契约，随 crate 维护 | 保留原地 |
| 30 | `crates/nexus-nat-traversal/MODULE.md` | crates/nexus-nat-traversal crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 31 | `crates/nexus-nat-wireup/MODULE.md` | crates/nexus-nat-wireup crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 32 | `crates/nexus-network/MODULE.md` | crates/nexus-network crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 33 | `crates/nexus-outbound-anytls/MODULE.md` | crates/nexus-outbound-anytls crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 34 | `crates/nexus-outbound-hysteria2/MODULE.md` | crates/nexus-outbound-hysteria2 crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 35 | `crates/nexus-outbound-shadowsocks/MODULE.md` | crates/nexus-outbound-shadowsocks crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 36 | `crates/nexus-outbound-shadowsocks/tests/kat/README.md` | shadowsocks KAT 测试目录说明，被 sip004_kat.rs 注释引用（线长算术钉死） | 保留原地（不可轻移） |
| 37 | `crates/nexus-outbound-trojan/MODULE.md` | crates/nexus-outbound-trojan crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 38 | `crates/nexus-outbound-vless/MODULE.md` | crates/nexus-outbound-vless crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 39 | `crates/nexus-outbound-vmess/MODULE.md` | crates/nexus-outbound-vmess crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 40 | `crates/nexus-path/MODULE.md` | crates/nexus-path crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 41 | `crates/nexus-planner/MODULE.md` | crates/nexus-planner crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 42 | `crates/nexus-platform-android/MODULE.md` | crates/nexus-platform-android crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 43 | `crates/nexus-platform-ios/MODULE.md` | crates/nexus-platform-ios crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 44 | `crates/nexus-platform-linux/MODULE.md` | crates/nexus-platform-linux crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 45 | `crates/nexus-platform-macos/MODULE.md` | crates/nexus-platform-macos crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 46 | `crates/nexus-platform-windows/MODULE.md` | crates/nexus-platform-windows crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 47 | `crates/nexus-platform/MODULE.md` | crates/nexus-platform crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 48 | `crates/nexus-plugin/MODULE.md` | crates/nexus-plugin crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 49 | `crates/nexus-policy/MODULE.md` | crates/nexus-policy crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 50 | `crates/nexus-projection/MODULE.md` | crates/nexus-projection crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 51 | `crates/nexus-proto/MODULE.md` | crates/nexus-proto crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 52 | `crates/nexus-proxy-config/MODULE.md` | crates/nexus-proxy-config crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 53 | `crates/nexus-proxy-transport/MODULE.md` | crates/nexus-proxy-transport crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 54 | `crates/nexus-proxy/MODULE.md` | crates/nexus-proxy crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 55 | `crates/nexus-registry/MODULE.md` | crates/nexus-registry crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 56 | `crates/nexus-scheduler/MODULE.md` | crates/nexus-scheduler crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 57 | `crates/nexus-service/MODULE.md` | crates/nexus-service crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 58 | `crates/nexus-session/MODULE.md` | crates/nexus-session crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 59 | `crates/nexus-session/amendments/2026-10-03-b1-disposed-record-gate.md` | nexus-session crate 契约修正案 B1（disposed record gate），随 crate 维护并被 metadata.json 固定 hash | 保留原地 |
| 60 | `crates/nexus-session/amendments/2026-10-03-b2-terminal-cleanup-replay.md` | nexus-session crate 契约修正案 B2（terminal cleanup replay），随 crate 维护并被 metadata.json 固定 hash | 保留原地 |
| 61 | `crates/nexus-storage/MODULE.md` | crates/nexus-storage crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 62 | `crates/nexus-transport/MODULE.md` | crates/nexus-transport crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 63 | `crates/nexus-turn/MODULE.md` | crates/nexus-turn crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 64 | `crates/nexus-web-gateway/MODULE.md` | crates/nexus-web-gateway crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 65 | `crates/nexus-web-gateway/USER_MANUAL.md` | nexus-web-gateway crate 用户手册（随 crate 维护） | 保留原地 |
| 66 | `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` | nexus-web-gateway crate 内文件模块评审记录（2026-10-11） | 保留原地 |
| 67 | `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` | nexus-web-gateway crate 内文件模块验证记录（2026-10-10） | 保留原地 |
| 68 | `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` | gateway 文件服务设计 V2（crate 内设计文档） | 保留原地 |
| 69 | `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md` | gateway 文件服务回顾记录（2026-10-11，随 crate 维护） | 保留原地 |
| 70 | `crates/nexus-web-gateway/docs/README.md` | nexus-web-gateway crate 文档目录索引 | 保留原地 |
| 71 | `crates/nexus-workspace-intel/MODULE.md` | crates/nexus-workspace-intel crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 72 | `crates/nexus-workspace/MODULE.md` | crates/nexus-workspace crate 模块契约，随该 crate 源码维护（harness [discovery]/[hooks.protected] 以 MODULE.md 通配消费） | 保留原地 |
| 73 | `engineering/evidence-schema/README.md` | Evidence Schema 规则说明（harness.toml [output].schema 指向该目录） | 保留原地 |
| 74 | `engineering/nexus-harness/MODULE.md` | nexus-harness 模块契约（CLI 命令契约 + Code Intelligence Contract），被多个工程场景 requirement 引用 | 保留原地（不可轻移） |
| 75 | `engineering/nexus-harness/fixtures/code-intel/MODULE.md` | code-intel 语义查询夹具模块契约（frozen anchors 行/列号是契约一部分） | 保留原地 |
| 76 | `engineering/plugins/README.md` | Harness 插件体系说明（预期插件类别清单） | 保留原地 |
| 77 | `engineering/sandbox-env-guard/README.md` | sandbox-env-guard 工具文档（mise 驱动的环境守卫方案，随工具维护） | 保留原地 |
| 78 | `engineering/sandbox-env-guard/quality/RUBRIC.md` | sandbox-env-guard 质量 rubric 与优化流程（随工具维护） | 保留原地 |
| 79 | `fuzz/README.md` | fuzz 目录说明（模糊测试组织） | 保留原地 |
| 80 | `fuzz/fuzz_targets/README.md` | fuzz_targets 目录说明 | 保留原地 |
| 81 | `scenarios/README.md` | scenarios 场景目录说明（场景包组织与运行约定） | 保留原地 |
| 82 | `scenarios/fixtures/n3-12-requester/README.md` | n3-12-requester fixture 说明，被 recovery manifest 以 repo_path 引用 | 保留原地（不可轻移） |
| 83 | `tests/README.md` | 测试体系说明，被 crates/nexus-session/Cargo.toml 与并发测试注释引用 | 保留原地（不可轻移） |
| 84 | `tests/concurrency/README.md` | 并发测试目录说明 | 保留原地 |
| 85 | `tests/integration/README.md` | 集成测试目录说明 | 保留原地 |
| 86 | `tests/regression/README.md` | 回归测试目录说明 | 保留原地 |

### 2.5 archive（归档）（154 份）

| # | 路径 | 判定理由 | 建议去向 |
|---|---|---|---|
| 1 | `.agents/batch-plan-layer-a.md` | 2026-09-29 A 层批量计划（选路收尾，已执行完毕的历史计划） | archive/ |
| 2 | `.agents/code-intelligence-followups.md` | Code Intelligence 独立 Review 后续待办与处置记录（round 3 COMMENTED） | archive/（被 green-evidence txt 引用） |
| 3 | `.agents/code-intelligence-phase-2-4-plan.md` | Code Intelligence Phase 2/3/4 工作计划（历史执行计划） | archive/（被 green-evidence txt 引用） |
| 4 | `.agents/code-quality-review-2026-10-16.md` | 云端 Agent 开发工程代码质量管理审查报告（2026-10-16） | archive/ |
| 5 | `.agents/deny-baseline-decisions.md` | cargo-deny 基线归因决策记录（2026-09-30，已完成批次） | archive/ |
| 6 | `.agents/knowledge/README.md` | 知识库说明（目录树与条目组织约定） | archive/ |
| 7 | `.agents/knowledge/entries/2026-09-19-p1-bidirectional-roundtrip.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 8 | `.agents/knowledge/entries/2026-09-19-virtual-subnet-pitfalls.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 9 | `.agents/knowledge/entries/2026-09-20-http204-latency-probe.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 10 | `.agents/knowledge/entries/2026-09-20-nat-hole-punching-review.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 11 | `.agents/knowledge/entries/2026-09-20-virtual-subnet-encrypted-dataplane.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 12 | `.agents/knowledge/entries/2026-09-20-virtual-subnet-static-routing.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 13 | `.agents/knowledge/entries/2026-09-21-cross-subnet-egress.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 14 | `.agents/knowledge/entries/2026-09-21-secure-store-pitfalls.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 15 | `.agents/knowledge/entries/2026-09-21-secure-store.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 16 | `.agents/knowledge/entries/2026-09-21-subnet-cli-toml.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 17 | `.agents/knowledge/entries/2026-09-21-tun-dataplane.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 18 | `.agents/knowledge/entries/2026-09-21-virtual-subnet-coord.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 19 | `.agents/knowledge/entries/2026-09-21-virtual-subnet-nat-probe.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 20 | `.agents/knowledge/entries/2026-09-22-bench-gate.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 21 | `.agents/knowledge/entries/2026-09-22-perf-bench.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 22 | `.agents/knowledge/entries/2026-09-24-proxy-outbound-dataplane.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 23 | `.agents/knowledge/entries/2026-09-25-schedule-contract-pitfall.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 24 | `.agents/knowledge/entries/2026-09-26-lineend-anchor-and-udp-flaky.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 25 | `.agents/knowledge/entries/2026-09-29-dijkstra-single-source.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 26 | `.agents/knowledge/entries/2026-09-29-disjoint-suurballe-implementation.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 27 | `.agents/knowledge/entries/2026-09-29-ecmp-predecessor-completeness.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 28 | `.agents/knowledge/entries/2026-09-29-fib-manager-fingerprint.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 29 | `.agents/knowledge/entries/2026-09-29-flow-hash-selection.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 30 | `.agents/knowledge/entries/2026-09-29-kshortest-yen-implementation.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 31 | `.agents/knowledge/entries/2026-09-29-lsa-codec-alloc-guard.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 32 | `.agents/knowledge/entries/2026-09-29-psk-empty-secret-semantics.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 33 | `.agents/knowledge/entries/2026-09-29-routing-strategy-assembly.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 34 | `.agents/knowledge/entries/2026-09-29-tcp-pump-deadlock-and-platform-scenario-gating.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 35 | `.agents/knowledge/entries/2026-09-30-coverage-run-flaky-timing-test.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 36 | `.agents/knowledge/entries/2026-09-30-e4-sketch-midstream-wrap-deadlock.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 37 | `.agents/knowledge/entries/2026-09-30-enum-discriminant-index.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 38 | `.agents/knowledge/entries/2026-09-30-fabric-active-path-semantics.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 39 | `.agents/knowledge/entries/2026-09-30-fabric-rebind-failure-arm.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 40 | `.agents/knowledge/entries/2026-09-30-inherent-trait-ufcs.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 41 | `.agents/knowledge/entries/2026-09-30-os-assemble-lo-unshare.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 42 | `.agents/knowledge/entries/2026-09-30-os-assemble-netlink-decision.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 43 | `.agents/knowledge/entries/2026-09-30-proxy-transport-atomic-recv.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 44 | `.agents/knowledge/entries/2026-09-30-proxy-transport-ss-e4-pitfalls.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 45 | `.agents/knowledge/entries/2026-09-30-shared-target-dir-stale-rmeta.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 46 | `.agents/knowledge/entries/2026-09-30-tcp-egress-review-fixes.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 47 | `.agents/knowledge/entries/2026-09-30-turn-e4-premature-drop.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 48 | `.agents/knowledge/entries/2026-09-30-two-char-domain-ambiguity.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 49 | `.agents/knowledge/entries/2026-09-30-unwrap-or-eager-eval.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 50 | `.agents/knowledge/entries/2026-09-30-watcher-mtime-granularity.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 51 | `.agents/knowledge/entries/2026-10-01-boost-v1-contract-first.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 52 | `.agents/knowledge/entries/2026-10-01-classifier-ewma-readonly.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 53 | `.agents/knowledge/entries/2026-10-01-composition-root-wiring-pitfalls.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 54 | `.agents/knowledge/entries/2026-10-01-e5-realnet-source-ip.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 55 | `.agents/knowledge/entries/2026-10-01-frozen-signature-isomorphic-deviation.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 56 | `.agents/knowledge/entries/2026-10-01-n1-datagram-flow-not-product-bug.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 57 | `.agents/knowledge/entries/2026-10-01-n1-e4-quit-timing-sent-vs-delivered.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 58 | `.agents/knowledge/entries/2026-10-01-quinn-proto-server-migration-trigger.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 59 | `.agents/knowledge/entries/2026-10-02-c2-conflict-id-ordering.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 60 | `.agents/knowledge/entries/2026-10-02-c2-shallow-guard-placement.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 61 | `.agents/knowledge/entries/2026-10-02-cli-unify-scenario-requirement-change.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 62 | `.agents/knowledge/entries/2026-10-02-connectivity-evaluation-placement.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 63 | `.agents/knowledge/entries/2026-10-02-crash-recovery-durable-markers.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 64 | `.agents/knowledge/entries/2026-10-02-harness-scenario-pipe-eof-hang.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 65 | `.agents/knowledge/entries/2026-10-02-harness-stderr-scenario-json.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 66 | `.agents/knowledge/entries/2026-10-02-n1-e3-shutdown-deadlock-root-cause.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 67 | `.agents/knowledge/entries/2026-10-02-nat-quality-crate-placement.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 68 | `.agents/knowledge/entries/2026-10-02-nat-t1t2-interface-alignment.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 69 | `.agents/knowledge/entries/2026-10-02-nat-t4-e4-debug.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 70 | `.agents/knowledge/entries/2026-10-02-nat-warnfix-adopt-requeue-demux.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 71 | `.agents/knowledge/entries/2026-10-02-p1-ingress-chain-status.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 72 | `.agents/knowledge/entries/2026-10-02-w4-cache-fuse-projection.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 73 | `.agents/knowledge/entries/2026-10-02-wireup-bind-stream-routing.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 74 | `.agents/knowledge/entries/2026-10-02-workspace-authority-v2.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 75 | `.agents/knowledge/entries/2026-10-02-workspace-intel-crate.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 76 | `.agents/knowledge/entries/2026-10-02-ws-gc-storage-governance.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 77 | `.agents/knowledge/entries/2026-10-03-arch-cleanup-dead-code.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 78 | `.agents/knowledge/entries/2026-10-03-n1-watcher-graceful-close.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 79 | `.agents/knowledge/entries/2026-10-03-n2-p01-persist-identity.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 80 | `.agents/knowledge/entries/2026-10-03-n2-p02-registry-discovery.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 81 | `.agents/knowledge/entries/2026-10-03-n2-p03-planner-thicken.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 82 | `.agents/knowledge/entries/2026-10-03-n2-p04-review-fix.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 83 | `.agents/knowledge/entries/2026-10-03-n2-p04-session-use.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 84 | `.agents/knowledge/entries/2026-10-03-n3-durable-acceptance.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 85 | `.agents/knowledge/entries/2026-10-03-n3-snapshot-roots.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 86 | `.agents/knowledge/entries/2026-10-04-n3-artifact-publication-authority.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 87 | `.agents/knowledge/entries/2026-10-04-n3-linux-executor-boundaries.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 88 | `.agents/knowledge/entries/2026-10-04-n3-localapi-and-mutual-auth-boundaries.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 89 | `.agents/knowledge/entries/2026-10-04-n3-requester-scope-and-recovery-lease.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 90 | `.agents/knowledge/entries/2026-10-04-n3-runtime-start-authority.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 91 | `.agents/knowledge/entries/2026-10-05-n3-authorized-download-progress.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 92 | `.agents/knowledge/entries/2026-10-05-n3-capacity-owner-and-session-recovery.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 93 | `.agents/knowledge/entries/2026-10-05-worktree-hooks-and-test-binaries.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 94 | `.agents/knowledge/entries/2026-10-06-n3-scoped-operator-grants.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 95 | `.agents/knowledge/entries/2026-10-06-skill-mining-method.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 96 | `.agents/knowledge/entries/2026-10-11-datachannel-label-routing-version-skew.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 97 | `.agents/knowledge/entries/2026-10-11-dataview-setuint64-dual-side-fixture.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 98 | `.agents/knowledge/entries/2026-10-11-harness-dirty-working-tree-digest-blind.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 99 | `.agents/knowledge/entries/2026-10-11-ice-host-candidate-bind-set-equality.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 100 | `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 101 | `.agents/knowledge/entries/2026-10-11-panic-abort-external-arithmetic-overflow.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 102 | `.agents/knowledge/entries/2026-10-11-pre-push-stale-tombstone-after-every-verify.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 103 | `.agents/knowledge/entries/2026-10-11-resource-quota-audit-before-independent-review.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 104 | `.agents/knowledge/entries/2026-10-11-single-loop-send-queue-head-blocking.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 105 | `.agents/knowledge/entries/2026-10-16-n3-negative-controls.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 106 | `.agents/knowledge/entries/2026-10-17-n3-upload-terminal-integrity.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 107 | `.agents/knowledge/entries/2026-10-19-expiry-error-classification.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 108 | `.agents/knowledge/entries/2026-10-19-scoped-lease-inherited-fd.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 109 | `.agents/knowledge/entries/2026-10-21-n3-staging-ledger-validation-cost.md` | append-only 历史知识条目（踩坑/模式/决策记录，默认全部保留不逐条审计） | archive/（被 .agents/knowledge/index.json 索引的条目随索引一并迁移） |
| 110 | `.agents/knowledge/netns-privileged-diag.md` | netns 特权环境诊断记录（历史排查） | archive/ |
| 111 | `.agents/provider-daemon-and-result-cache-plan.md` | 自称“设计期的历史文档，不是契约”，四处已被后续裁决取代（以 MODULE.md 为准） | archive/（与 MODULE.md 的冲突见冲突项 C8） |
| 112 | `.evidence/red-n2-p0-0/RED-EVIDENCE.md` | N2 P0-0 契约冻结 Red Evidence 案卷（历史红灯证据） | archive/ |
| 113 | `.evidence/review-g11-ice-fix-qoder-r1/findings.md` | review-g11-ice-fix 评审案卷（Verdict COMMENTED，写入范围仅限 .evidence 目录） | archive/ |
| 114 | `.grill/decisions.md` | grill 阶段待拍板问题的直接决策记录（#7 Flow-session） | archive/ |
| 115 | `.grill/spec-draft.md` | #7 Flow-session 启用 Spec 草稿（grill 阶段） | archive/ |
| 116 | `.pee/runs/2026-10-16-e2e-test-system/report.md` | PEE run 2026-10-16 汇总报告（阶段结论与 evidence 索引，历史 run 产物） | archive/（被 feature-list.json 以 artifact 引用） |
| 117 | `docs/CLI_FRONTEND_DESIGN.md` | 自我标注 superseded（2026-09-20，已被 thin-client 架构取代），保留作历史参考 | archive/ |
| 118 | `docs/DAEMON_RUNTIME_OWNERSHIP.md` | Daemon Root 所有权基线清单（行号以 ebdf11d 为准的快照，AC6） | archive/ |
| 119 | `docs/DOC-AUDIT-2026-10-06.md` | 2026-10-06 文档现状审计报告（历史快照；其 276 计数与现存 290 不一致，见冲突项 C5） | archive/ |
| 120 | `docs/N3-1-IMPLEMENTATION.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 121 | `docs/N3-11-14-EXECUTION-PLAN.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 122 | `docs/N3-2-IMPLEMENTATION.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 123 | `docs/N3-3-LINUX-EXECUTOR.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 124 | `docs/N3-3-RUNTIME-FOUNDATION.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 125 | `docs/N3-4-ARTIFACT-DELIVERY.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 126 | `docs/N3-5-PARALLEL-PLAN.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 127 | `docs/N3-6-PARALLEL-PLAN.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 128 | `docs/N3-7-ENGINEERING-PLAN.md` | N3 已完成批次的实现/计划记录（各批次范围、入口与验收边界的历史留档） | archive/ |
| 129 | `docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md` | Agent Semantic Code Intelligence 提案（已落地为 harness MODULE.md 的 Code Intelligence Contract） | archive/（被 ~20 个工程场景 requirement 引用，不可轻移） |
| 130 | `docs/bugfix/path-planner-p0-amendments.md` | bugfix/path-planner-p0 批次的契约修正案（T1 P0 四 bug，已执行完毕） | archive/ |
| 131 | `docs/foundation/PATH-LAYER-PHASE2.md` | 路径层 Phase 2 决策记录（2026-09-30 已决策，L3 决策层） | archive/ |
| 132 | `docs/foundation/PROJECTION-LAYER-PHASE3.md` | 投影层 Phase 3 决策记录（2026-09-30 已决策，L3 决策层） | archive/ |
| 133 | `docs/foundation/PROJECTION-ROUTING-PHASE3B1.md` | Phase 3b-1 统一路由+本地出口决策记录（2026-09-30 已决策，L3 决策层） | archive/ |
| 134 | `docs/protocols/bootstrap-join/01-design-v1-draft.md` | Bootstrap 自动入网 v1 设计初稿（README 自称仅作历史留档，部分判断已被评审更正） | archive/ |
| 135 | `docs/protocols/bootstrap-join/02-review.md` | v1 设计独立评审报告（7 阻断项 S1-S7 + 3 事实更正，历史评审案卷） | archive/ |
| 136 | `docs/protocols/interop/fix/hysteria2/root-cause.md` | hysteria2 协议互操作修复批次根因报告（S27 系列，被 recompute-verdicts.py glob 列举进 MATRIX） | archive/（不可轻移，移动会破坏 MATRIX 生成） |
| 137 | `docs/protocols/interop/fix/shadowsocks/root-cause.md` | shadowsocks 协议互操作修复批次根因报告（S27 系列，被 recompute-verdicts.py glob 列举进 MATRIX） | archive/（不可轻移，移动会破坏 MATRIX 生成） |
| 138 | `docs/protocols/interop/fix/transport/root-cause.md` | transport 协议互操作修复批次根因报告（S27 系列，被 recompute-verdicts.py glob 列举进 MATRIX） | archive/（不可轻移，移动会破坏 MATRIX 生成） |
| 139 | `docs/protocols/interop/fix/trojan/root-cause.md` | trojan 协议互操作修复批次根因报告（S27 系列，被 recompute-verdicts.py glob 列举进 MATRIX） | archive/（不可轻移，移动会破坏 MATRIX 生成） |
| 140 | `docs/protocols/interop/fix/vless/root-cause.md` | vless 协议互操作修复批次根因报告（S27 系列，被 recompute-verdicts.py glob 列举进 MATRIX） | archive/（不可轻移，移动会破坏 MATRIX 生成） |
| 141 | `docs/protocols/interop/prediction-check.md` | protocol-interop-fixes-1 轮次的预测冻结核对记录（步骤 2/3 实测对比） | archive/ |
| 142 | `docs/recovery/2026-10-20/README.md` | 2026-10-20 代码恢复归档说明（取证快照 manifest 使用指南） | archive/ |
| 143 | `docs/recovery/2026-10-21/README.md` | 2026-10-21 N3 恢复集成记录（dbb511a 恢复内容与验证结论） | archive/ |
| 144 | `docs/source-audit/00-overview.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 145 | `docs/source-audit/01-cli-apps-nexus.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 146 | `docs/source-audit/02-daemon-n3-durable.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 147 | `docs/source-audit/03-dataplane-connectivity-projection.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 148 | `docs/source-audit/04-proxy-outbound-nat.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 149 | `docs/source-audit/05-core-platform-harness.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 150 | `docs/source-audit/06-implementation-status.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 151 | `docs/source-audit/07-comment-errors.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 152 | `docs/source-audit/08-verification-log.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 153 | `docs/source-audit/09-incremental-audit.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |
| 154 | `docs/source-audit/AUDIT-SPEC.md` | 基于 e6ccf8b（及 d50d8fe 增量）基线的纯源码逆向审计系列（分片审计/状态矩阵/注释错误/复核日志/共享口径，历史快照） | archive/ |

## 3. 「不可轻移」清单

共 **214** 份 .md 查得以路径引用证据（被代码、CI workflow、构建脚本、工程配置、机器索引/清单或其他文档引用）。查不到引用证据的文件未列入。

引用证据分六类：A 工程配置与机器契约；B 代码/测试；C 脚本与工具；D 场景/策略配置；E 索引与 manifest；F 其他文档（markdown 链接或行内代码路径）。

### 3.A 工程配置与机器契约（通配消费，整组不可轻移）

| # | 被引用文件 | 引用方 | 说明 |
|---|---|---|---|
| 1 | `apps/nexusd/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 2 | `apps/nexus/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 3 | `apps/nexus-platform-host/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 4 | `crates/nexus-auth/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 5 | `crates/nexus-compute/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 6 | `crates/nexus-connectivity/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 7 | `crates/nexus-control-api/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 8 | `crates/nexus-delivery/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 9 | `crates/nexus-diagnostics/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 10 | `crates/nexus-discovery/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 11 | `crates/nexus-dns/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 12 | `crates/nexus-domain/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 13 | `crates/nexus-fabric/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 14 | `crates/nexus-flow-session/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 15 | `crates/nexus-ingress/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 16 | `crates/nexus-measurement/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 17 | `crates/nexus-nat-quality/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 18 | `crates/nexus-nat-traversal/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 19 | `crates/nexus-nat-wireup/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 20 | `crates/nexus-network/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 21 | `crates/nexus-outbound-anytls/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 22 | `crates/nexus-outbound-hysteria2/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 23 | `crates/nexus-outbound-shadowsocks/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 24 | `crates/nexus-outbound-trojan/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 25 | `crates/nexus-outbound-vless/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 26 | `crates/nexus-outbound-vmess/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 27 | `crates/nexus-path/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 28 | `crates/nexus-planner/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 29 | `crates/nexus-platform-android/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 30 | `crates/nexus-platform-ios/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 31 | `crates/nexus-platform-linux/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 32 | `crates/nexus-platform-macos/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 33 | `crates/nexus-platform/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 34 | `crates/nexus-platform-windows/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 35 | `crates/nexus-plugin/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 36 | `crates/nexus-policy/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 37 | `crates/nexus-projection/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 38 | `crates/nexus-proto/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 39 | `crates/nexus-proxy-config/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 40 | `crates/nexus-proxy/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 41 | `crates/nexus-proxy-transport/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 42 | `crates/nexus-registry/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 43 | `crates/nexus-scheduler/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 44 | `crates/nexus-service/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 45 | `crates/nexus-session/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 46 | `crates/nexus-storage/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 47 | `crates/nexus-transport/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 48 | `crates/nexus-turn/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 49 | `crates/nexus-web-gateway/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 50 | `crates/nexus-workspace-intel/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 51 | `crates/nexus-workspace/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 52 | `engineering/nexus-harness/fixtures/code-intel/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 53 | `engineering/nexus-harness/MODULE.md` | harness.toml [discovery].module_contract = "MODULE.md" 与 [hooks.protected].paths 含 "**/MODULE.md" | harness 以 MODULE.md 通配符发现/保护模块契约；移动或改名会破坏模块契约发现与 pre-push 门禁 |
| 54 | `.agents/skills/nexus-task/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 55 | `.agents/skills/nexus-contract-first/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 56 | `.agents/skills/nexus-review/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 57 | `.agents/skills/nexus-knowledge/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 58 | `.agents/skills/nexus-evidence/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 59 | `.agents/skills/nexus-multiagent/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 60 | `.agents/skills/nexus-selfrepair/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 61 | `.agents/skills/nexus-test-review/SKILL.md` | harness.toml [skills].entries 列表 | harness 按条目名加载项目级技能；移动会破坏技能加载 |
| 62 | `.agents/knowledge/entries/2026-09-19-p1-bidirectional-roundtrip.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 63 | `.agents/knowledge/entries/2026-09-19-virtual-subnet-pitfalls.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 64 | `.agents/knowledge/entries/2026-09-20-http204-latency-probe.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 65 | `.agents/knowledge/entries/2026-09-20-virtual-subnet-static-routing.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 66 | `.agents/knowledge/entries/2026-09-26-lineend-anchor-and-udp-flaky.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 67 | `.agents/knowledge/entries/2026-09-29-dijkstra-single-source.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 68 | `.agents/knowledge/entries/2026-09-29-disjoint-suurballe-implementation.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 69 | `.agents/knowledge/entries/2026-09-29-ecmp-predecessor-completeness.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 70 | `.agents/knowledge/entries/2026-09-29-fib-manager-fingerprint.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 71 | `.agents/knowledge/entries/2026-09-29-flow-hash-selection.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 72 | `.agents/knowledge/entries/2026-09-29-kshortest-yen-implementation.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 73 | `.agents/knowledge/entries/2026-09-29-lsa-codec-alloc-guard.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 74 | `.agents/knowledge/entries/2026-09-29-psk-empty-secret-semantics.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 75 | `.agents/knowledge/entries/2026-09-29-routing-strategy-assembly.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 76 | `.agents/knowledge/entries/2026-09-29-tcp-pump-deadlock-and-platform-scenario-gating.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 77 | `.agents/knowledge/entries/2026-09-30-coverage-run-flaky-timing-test.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 78 | `.agents/knowledge/entries/2026-09-30-enum-discriminant-index.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 79 | `.agents/knowledge/entries/2026-09-30-inherent-trait-ufcs.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 80 | `.agents/knowledge/entries/2026-09-30-os-assemble-lo-unshare.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 81 | `.agents/knowledge/entries/2026-09-30-os-assemble-netlink-decision.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 82 | `.agents/knowledge/entries/2026-09-30-shared-target-dir-stale-rmeta.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 83 | `.agents/knowledge/entries/2026-09-30-unwrap-or-eager-eval.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 84 | `.agents/knowledge/entries/2026-10-01-frozen-signature-isomorphic-deviation.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 85 | `.agents/knowledge/entries/2026-10-02-cli-unify-scenario-requirement-change.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 86 | `.agents/knowledge/entries/2026-10-02-nat-quality-crate-placement.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 87 | `.agents/knowledge/entries/2026-10-03-arch-cleanup-dead-code.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 88 | `.agents/knowledge/entries/2026-10-03-n1-watcher-graceful-close.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 89 | `.agents/knowledge/entries/2026-10-03-n2-p03-planner-thicken.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 90 | `.agents/knowledge/entries/2026-10-03-n2-p04-review-fix.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 91 | `.agents/knowledge/entries/2026-10-03-n2-p04-session-use.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 92 | `.agents/knowledge/entries/2026-10-03-n3-durable-acceptance.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 93 | `.agents/knowledge/entries/2026-10-03-n3-snapshot-roots.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 94 | `.agents/knowledge/entries/2026-10-04-n3-artifact-publication-authority.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 95 | `.agents/knowledge/entries/2026-10-04-n3-linux-executor-boundaries.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 96 | `.agents/knowledge/entries/2026-10-04-n3-localapi-and-mutual-auth-boundaries.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 97 | `.agents/knowledge/entries/2026-10-04-n3-requester-scope-and-recovery-lease.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 98 | `.agents/knowledge/entries/2026-10-04-n3-runtime-start-authority.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 99 | `.agents/knowledge/entries/2026-10-05-n3-authorized-download-progress.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 100 | `.agents/knowledge/entries/2026-10-05-n3-capacity-owner-and-session-recovery.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 101 | `.agents/knowledge/entries/2026-10-05-worktree-hooks-and-test-binaries.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 102 | `.agents/knowledge/entries/2026-10-06-n3-scoped-operator-grants.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 103 | `.agents/knowledge/entries/2026-10-06-skill-mining-method.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 104 | `.agents/knowledge/entries/2026-10-11-datachannel-label-routing-version-skew.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 105 | `.agents/knowledge/entries/2026-10-11-dataview-setuint64-dual-side-fixture.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 106 | `.agents/knowledge/entries/2026-10-11-harness-dirty-working-tree-digest-blind.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 107 | `.agents/knowledge/entries/2026-10-11-ice-host-candidate-bind-set-equality.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 108 | `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 109 | `.agents/knowledge/entries/2026-10-11-panic-abort-external-arithmetic-overflow.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 110 | `.agents/knowledge/entries/2026-10-11-pre-push-stale-tombstone-after-every-verify.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 111 | `.agents/knowledge/entries/2026-10-11-resource-quota-audit-before-independent-review.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 112 | `.agents/knowledge/entries/2026-10-11-single-loop-send-queue-head-blocking.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 113 | `.agents/knowledge/entries/2026-10-16-n3-negative-controls.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 114 | `.agents/knowledge/entries/2026-10-17-n3-upload-terminal-integrity.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 115 | `.agents/knowledge/entries/2026-10-19-expiry-error-classification.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 116 | `.agents/knowledge/entries/2026-10-19-scoped-lease-inherited-fd.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |
| 117 | `.agents/knowledge/entries/2026-10-21-n3-staging-ledger-validation-cost.md` | .agents/knowledge/index.json 的 "file" 字段（machine-readable index） | index.json 以 "file": "entries/xxx.md" 登记条目；移动不同步索引会破坏知识检索 |

### 3.B 工程配置/代码/脚本/manifest 显式路径引用

| # | 被引用文件（类别） | 引用方文件 |
|---|---|---|
| 1 | `.agents/code-intelligence-followups.md`（archive） | `.agents/green-evidence-code-intelligence.txt` |
| 2 | `.agents/code-intelligence-phase-2-4-plan.md`（archive） | `.agents/green-evidence-code-intelligence.txt` |
| 3 | `.agents/provider-daemon-and-result-cache-plan.md`（archive） | `.agents/green-evidence-code-intelligence.txt` |
| 4 | `.pee/runs/2026-10-16-e2e-test-system/report.md`（archive） | `.pee/runs/2026-10-16-e2e-test-system/feature-list.json`（artifact 字段） |
| 5 | `AGENTS.md`（current） | `.devcontainer/setup.sh`; `apps/nexus/src/mesh.rs`; `apps/nexus/src/strategy_watcher.rs`; `apps/nexusd/src/watcher.rs`; `apps/nexusd/src/workspace.rs`; `crates/nexus-connectivity/src/lib.rs`; `crates/nexus-discovery/src/lib.rs`; `crates/nexus-discovery/src/paired.rs`; `crates/nexus-domain/src/lib.rs`; `crates/nexus-flow-session/src/manager.rs`; `crates/nexus-network/examples/n1_roam.rs`; `crates/nexus-network/examples/n1_roam_realnet.rs`; `crates/nexus-network/src/n1/link.rs`; `crates/nexus-network/src/n1/mod.rs`; `crates/nexus-network/src/n1/pump.rs`; `crates/nexus-network/src/n1/session.rs`; `crates/nexus-platform-linux/src/dns.rs`; `crates/nexus-platform-windows/src/lib.rs`; `crates/nexus-session/src/lib.rs`; `crates/nexus-workspace-intel/src/lib.rs`; `crates/nexus-workspace/src/gc.rs`; `crates/nexus-workspace/src/lib.rs`; `engineering/nexus-harness/src/config.rs`; `engineering/nexus-harness/src/evidence.rs`; `engineering/nexus-harness/src/gates.rs`; `engineering/sandbox-env-guard/mise.toml`; `fuzz/fuzz_targets/policy_planner_no_panic.rs`; `harness.toml`; `nexus-sync.ps1`; `nexus-sync.sh`; `policies/quality.toml`; `scenarios/fixtures/n3-12-requester/metadata.json`; `scenarios/product/workspace_gc.toml`; `tests/concurrency/session_outcome_race.rs` |
| 6 | `ARCHITECTURE.md`（contract） | `crates/nexus-flow-session/src/lib.rs`; `harness.toml`; `scenarios/fixtures/n3-12-requester/metadata.json`; `scenarios/product/flow_session_mapping.toml`; `scripts/agent-zero-deps-check.sh` |
| 7 | `CONTRACT-scenario-pack.md`（contract） | `engineering/nexus-harness/src/scenario.rs`; `engineering/nexus-harness/src/scenario_cmd.rs` |
| 8 | `CONTRIBUTING.md`（current） | `.github/workflows/commitlint.yml`（echo 提示 See CONTRIBUTING.md） |
| 9 | `DEV-ENV.md`（current） | `.devcontainer/setup.sh`; `rust-toolchain.toml`; `scripts/remote-dev-setup.sh` |
| 10 | `DEVELOPMENT.md`（contract） | `engineering/nexus-harness/src/code_intel/mod.rs`; `harness.toml`; `scenarios/engineering/harness_verify_fast_evidence.toml` |
| 11 | `FILE_MANIFEST.md`（current） | `.agents/green-evidence-code-intelligence.txt`（文本引用）; `.agents/red-evidence-daemon.txt`（文本引用） |
| 12 | `PRODUCT.md`（contract） | `apps/nexus/src/lib.rs`; `apps/nexus/src/main.rs`; `crates/nexus-connectivity/src/encryption.rs`; `crates/nexus-flow-session/src/flow.rs`; `crates/nexus-proxy-config/src/lib.rs`; `crates/nexus-proxy/src/lib.rs`; `engineering/e2e/_render_coverage.py`; `engineering/nexus-harness/src/gates.rs`; `harness.toml`; `policies/architecture.toml`; `scenarios/engineering/bench_gate_verdicts.toml`; `scenarios/fixtures/n3-12-requester/metadata.json`; `scenarios/platform/os_assemble.toml`; `scenarios/platform/virtual_packet_interface.toml`; `scenarios/platform/windows_system_proxy.toml`; `scenarios/platform/workspace_projection_channels.toml`; `scenarios/platform/workspace_projection_fallback.toml`; `scenarios/product/auto_discovery.toml`; `scenarios/product/auto_reconnect.toml`; `scenarios/product/bandwidth_policy.toml`; `scenarios/product/bandwidth_qos.toml`; `scenarios/product/bootstrap_join.toml`; `scenarios/product/certificate_manager.toml`; `scenarios/product/cli-run-command.toml`; `scenarios/product/cli_compute_jobs.toml`; `scenarios/product/cli_connectivity_candidates.toml`; `scenarios/product/cli_connectivity_links.toml`; `scenarios/product/cli_connectivity_probe.toml`; `scenarios/product/cli_diagnose.toml`; `scenarios/product/cli_dns_providers.toml`; `scenarios/product/cli_dns_resolve.toml`; `scenarios/product/cli_subnet.toml`; `scenarios/product/cli_workspace_cache.toml`; `scenarios/product/cli_workspace_conflicts.toml`; `scenarios/product/compression.toml`; `scenarios/product/config_hot_reload.toml`; `scenarios/product/config_hot_reload_watch.toml`; `scenarios/product/connection_pool.toml`; `scenarios/product/connection_pool_real.toml`; `scenarios/product/connectivity_carrier_split.toml`; `scenarios/product/connectivity_failure_rollback.toml`; `scenarios/product/coord_core.toml`; `scenarios/product/coord_join_loopback.toml`; `scenarios/product/cross_subnet.toml`; `scenarios/product/daemon_real_host_auth_denied.toml`; `scenarios/product/daemon_real_host_flow.toml`; `scenarios/product/daemon_real_relay_flow.toml`; `scenarios/product/daemon_real_socks_proxy_flow.toml`; `scenarios/product/daemon_rejects_unknown_resource.toml`; `scenarios/product/daemon_run_remote_service_flow.toml`; `scenarios/product/daemon_run_with_command.toml`; `scenarios/product/daemon_run_workspace_flow.toml`; `scenarios/product/daemon_tun_dataplane.toml`; `scenarios/product/decentralized_join_config.toml`; `scenarios/product/dijkstra_fib.toml`; `scenarios/product/discovery_enhanced.toml`; `scenarios/product/disjoint.toml`; `scenarios/product/dns_exit_binding.toml`; `scenarios/product/dns_ipcidr_rule.toml`; `scenarios/product/dns_rule_server_selection.toml`; `scenarios/product/ecmp.toml`; `scenarios/product/fabric-mutual-auth.toml`; `scenarios/product/failover.toml`; `scenarios/product/failover_health.toml`; `scenarios/product/fib_forwarding.toml`; `scenarios/product/fib_manager.toml`; `scenarios/product/fib_manager_shared.toml`; `scenarios/product/firewall_rules.toml`; `scenarios/product/flow_hash.toml`; `scenarios/product/flow_session_mapping.toml`; `scenarios/product/fragmentation.toml`; `scenarios/product/geoip_nex_roundtrip.toml`; `scenarios/product/geoip_source_ip2region.toml`; `scenarios/product/geosite_nex_roundtrip.toml`; `scenarios/product/graceful_exit.toml`; `scenarios/product/graceful_exit_real.toml`; `scenarios/product/group_isolation.toml`; `scenarios/product/health_check.toml`; `scenarios/product/health_check_real.toml`; `scenarios/product/hole_punch_multi.toml`; `scenarios/product/identity_auto_exchange.toml`; `scenarios/product/internet_access_flow.toml`; `scenarios/product/k_shortest.toml`; `scenarios/product/link_encryption.toml`; `scenarios/product/log_level.toml`; `scenarios/product/lsa_discovery.toml`; `scenarios/product/mesh_dns.toml`; `scenarios/product/multihop_routing.toml`; `scenarios/product/n2-grant-deny-audit.toml`; `scenarios/product/n2-grant-expired.toml`; `scenarios/product/n2-plan-explain-estimate.toml`; `scenarios/product/n2-plan-explain-history.toml`; `scenarios/product/n2-plan-preview.toml`; `scenarios/product/n2-plan-unknown.toml`; `scenarios/product/n2-provider-offline.toml`; `scenarios/product/n2-resource-list.toml`; `scenarios/product/n2-resource-publish.toml`; `scenarios/product/n2-resource-revoke.toml`; `scenarios/product/n2-resource-show.toml`; `scenarios/product/n2-revoked-resource-unusable.toml`; `scenarios/product/n2-session-close.toml`; `scenarios/product/n2-session-list.toml`; `scenarios/product/n2-session-watch-unknown.toml`; `scenarios/product/n2-session-watch.toml`; `scenarios/product/n2-use-loop.toml`; `scenarios/product/n2-use-probe-honesty.toml`; `scenarios/product/n2-use-rejects-command.toml`; `scenarios/product/n2-use-unknown.toml`; `scenarios/product/n3-10-operator-grant.toml`; `scenarios/product/n3-11-provider-init.toml`; `scenarios/product/n3-12-snapshot-staging.toml`; `scenarios/product/n3-8-foundation-boundary.toml`; `scenarios/product/n3-9-artifact-cli.toml`; `scenarios/product/n3-acceptance-crash.toml`; `scenarios/product/n3-artifact-integrity.toml`; `scenarios/product/n3-artifact-missing.toml`; `scenarios/product/n3-artifact-resume.toml`; `scenarios/product/n3-authorization.toml`; `scenarios/product/n3-cancel-pending.toml`; `scenarios/product/n3-cancel-race.toml`; `scenarios/product/n3-client-reattach.toml`; `scenarios/product/n3-crash-reconcile.toml`; `scenarios/product/n3-environment-mismatch.toml`; `scenarios/product/n3-gc-roots.toml`; `scenarios/product/n3-idempotency-conflict.toml`; `scenarios/product/n3-idempotency-expiry.toml`; `scenarios/product/n3-idempotency.toml`; `scenarios/product/n3-input-integrity.toml`; `scenarios/product/n3-localapi-v1-boundary.toml`; `scenarios/product/n3-log-limit.toml`; `scenarios/product/n3-nonzero-exit.toml`; `scenarios/product/n3-path-safety.toml`; `scenarios/product/n3-snapshot-immutable.toml`; `scenarios/product/n3-submit.toml`; `scenarios/product/n3-timeout.toml`; `scenarios/product/n3-unsupported-isolation.toml`; `scenarios/product/node_disjoint.toml`; `scenarios/product/node_priority.toml`; `scenarios/product/node_tags.toml`; `scenarios/product/observability_compute_jobs.toml`; `scenarios/product/observability_connectivity_candidates.toml`; `scenarios/product/observability_connectivity_links.toml`; `scenarios/product/observability_connectivity_probe.toml`; `scenarios/product/observability_diagnose.toml`; `scenarios/product/observability_dns_cache.toml`; `scenarios/product/observability_dns_providers.toml`; `scenarios/product/observability_dns_resolve.toml`; `scenarios/product/observability_plan_explain.toml`; `scenarios/product/observability_session_watch.toml`; `scenarios/product/observability_status.toml`; `scenarios/product/observability_unsupported.toml`; `scenarios/product/observability_workspace_cache.toml`; `scenarios/product/observability_workspace_conflicts.toml`; `scenarios/product/observability_workspace_heads.toml`; `scenarios/product/performance_benchmark.toml`; `scenarios/product/pipeline_compression.toml`; `scenarios/product/pipeline_firewall.toml`; `scenarios/product/pipeline_fragmentation.toml`; `scenarios/product/pipeline_qos.toml`; `scenarios/product/proxy_clash_subscription_parse.toml`; `scenarios/product/proxy_default_match.toml`; `scenarios/product/proxy_extended_rules.toml`; `scenarios/product/proxy_geoip_rule.toml`; `scenarios/product/proxy_geosite_rule.toml`; `scenarios/product/proxy_http_mixed_inbound.toml`; `scenarios/product/proxy_ipcidr_rule.toml`; `scenarios/product/proxy_loadbalance_group.toml`; `scenarios/product/proxy_outbound_shadowsocks_flow.toml`; `scenarios/product/proxy_outbound_trojan_flow.toml`; `scenarios/product/proxy_outbound_vless_flow.toml`; `scenarios/product/proxy_relay_group.toml`; `scenarios/product/proxy_rule_invalid.toml`; `scenarios/product/proxy_rule_provider_fetch.toml`; `scenarios/product/proxy_rule_provider_fetch_https.toml`; `scenarios/product/proxy_rule_set.toml`; `scenarios/product/proxy_selector_group.toml`; `scenarios/product/proxy_shadowsocks_adapter.toml`; `scenarios/product/proxy_shadowsocks_real_tcp.toml`; `scenarios/product/proxy_socks5_domain_rule.toml`; `scenarios/product/proxy_speedtest.toml`; `scenarios/product/proxy_speedtest_http204.toml`; `scenarios/product/proxy_speedtest_http204_bad_status.toml`; `scenarios/product/proxy_speedtest_http204_loopback.toml`; `scenarios/product/proxy_speedtest_loopback.toml`; `scenarios/product/proxy_subscription_online_update.toml`; `scenarios/product/proxy_trojan_adapter.toml`; `scenarios/product/proxy_trojan_auth_rejected.toml`; `scenarios/product/proxy_trojan_header_format.toml`; `scenarios/product/proxy_trojan_node_config.toml`; `scenarios/product/proxy_trojan_real_tls_params.toml`; `scenarios/product/proxy_tun_inbound.toml`; `scenarios/product/proxy_urltest_group.toml`; `scenarios/product/proxy_vmess_adapter.toml`; `scenarios/product/psk_handshake_admission.toml`; `scenarios/product/relay_fallback.toml`; `scenarios/product/remote_compute_job_flow.toml`; `scenarios/product/remote_compute_rejected_rollback.toml`; `scenarios/product/remote_connectivity_failure_rollback.toml`; `scenarios/product/remote_internet_access_flow.toml`; `scenarios/product/remote_nat_relay_fallback_flow.toml`; `scenarios/product/remote_network_auth_rejected_rollback.toml`; `scenarios/product/remote_presence_dynamic_flow.toml`; `scenarios/product/remote_presence_expired_rollback.toml`; `scenarios/product/remote_presence_network_discovery_flow.toml`; `scenarios/product/remote_presence_network_unknown_rollback.toml`; `scenarios/product/remote_relay_unavailable_rollback.toml`; `scenarios/product/remote_service_access_flow.toml`; `scenarios/product/remote_workspace_commit_flow.toml`; `scenarios/product/remote_workspace_rejected_rollback.toml`; `scenarios/product/resource_session_lifecycle.toml`; `scenarios/product/routing_strategy.toml`; `scenarios/product/schedule_cli_flow.toml`; `scenarios/product/schedule_cli_reachable.toml`; `scenarios/product/schedule_flow.toml`; `scenarios/product/secure_state.toml`; `scenarios/product/secure_store.toml`; `scenarios/product/smart_retry.toml`; `scenarios/product/smart_retry_real.toml`; `scenarios/product/socks5_handshake.toml`; `scenarios/product/strategy_extended.toml`; `scenarios/product/strategy_hot_reload.toml`; `scenarios/product/strategy_watcher.toml`; `scenarios/product/subnet_daemon.toml`; `scenarios/product/subnet_punch_cli.toml`; `scenarios/product/subnet_punch_status.toml`; `scenarios/product/traffic_stats.toml`; `scenarios/product/tun_dataplane.toml`; `scenarios/product/turn_relay_allocate.toml`; `scenarios/product/virtual_subnet_encrypted_3node.toml`; `scenarios/product/virtual_subnet_holepunch.toml`; `scenarios/product/virtual_subnet_mesh_3node.toml`; `scenarios/product/virtual_subnet_nat_probe.toml`; `scenarios/product/virtual_subnet_tunnel.toml`; `scenarios/product/weighted_selection.toml`; `scenarios/product/workspace_offline_merge.toml`; `scripts/agent-zero-deps-check.sh` |
| 13 | `crates/nexus-outbound-shadowsocks/tests/kat/README.md`（代码内嵌文档） | `crates/nexus-outbound-shadowsocks/tests/sip004_kat.rs` |
| 14 | `crates/nexus-session/amendments/2026-10-03-b1-disposed-record-gate.md`（代码内嵌文档） | `scenarios/fixtures/n3-12-requester/metadata.json` |
| 15 | `crates/nexus-session/amendments/2026-10-03-b2-terminal-cleanup-replay.md`（代码内嵌文档） | `scenarios/fixtures/n3-12-requester/metadata.json` |
| 16 | `docs/CODE-INTELLIGENCE-KNOWN-ISSUES.md`（current） | `.agents/green-evidence-code-intelligence.txt`（文本引用 G4/G4b） |
| 17 | `docs/DAEMON_ARCHITECTURE.md`（current） | `apps/nexusd/src/assembly.rs`; `apps/nexusd/src/config.rs`; `scenarios/product/boost_v1.toml`; `scenarios/product/composition_root.toml`; `scenarios/product/dataplane_unified.toml`; `scenarios/product/dns_unified.toml`; `scenarios/product/multipath.toml`; `scenarios/product/qos_cake.toml`; `scenarios/product/unified_classifier.toml` |
| 18 | `docs/N3-11-14-EXECUTION-PLAN.md`（archive） | `docs/recovery/2026-10-20/unverified-code-export-manifest.json`（repo_path）; `docs/recovery/2026-10-21/document-integration-manifest.json`（repo_path）; `docs/recovery/2026-10-21/printed-path-coverage.json`（path） |
| 19 | `docs/N3-11-PROVIDER-INIT-CONTRACT.md`（contract） | `docs/recovery/2026-10-20/canonical-export-manifest.json`（repo_path）; `docs/recovery/2026-10-20/unverified-code-export-manifest.json`（repo_path）; `docs/recovery/2026-10-21/printed-path-coverage.json`（path） |
| 20 | `docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md`（contract） | `scenarios/fixtures/n3-12-requester/metadata.json` |
| 21 | `docs/N3-13-REMOTE-TASK-CONTRACT.md`（contract） | `docs/recovery/2026-10-20/unverified-code-export-manifest.json`（repo_path）; `docs/recovery/2026-10-21/document-integration-manifest.json`（repo_path）; `docs/recovery/2026-10-21/printed-path-coverage.json`（path） |
| 22 | `docs/N3-13A-BOUNDED-MTLS-CONTRACT-DRAFT.md`（contract） | `docs/recovery/2026-10-20/unverified-code-export-manifest.json`（repo_path）; `docs/recovery/2026-10-21/document-integration-manifest.json`（repo_path）; `docs/recovery/2026-10-21/printed-path-coverage.json`（path） |
| 23 | `docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md`（archive） | `scenarios/engineering/code_intelligence_budget_count.toml`; `scenarios/engineering/code_intelligence_budget_truncation.toml`; `scenarios/engineering/code_intelligence_callees.toml`; `scenarios/engineering/code_intelligence_callers.toml`; `scenarios/engineering/code_intelligence_context_anchors.toml`; `scenarios/engineering/code_intelligence_context_no_fake_semantics.toml`; `scenarios/engineering/code_intelligence_context_scope_guard.toml`; `scenarios/engineering/code_intelligence_daemon_lifecycle.toml`; `scenarios/engineering/code_intelligence_definition.toml`; `scenarios/engineering/code_intelligence_diagnostics_advisory.toml`; `scenarios/engineering/code_intelligence_diagnostics_item_shape.toml`; `scenarios/engineering/code_intelligence_hover.toml`; `scenarios/engineering/code_intelligence_implementations.toml`; `scenarios/engineering/code_intelligence_mcp_handshake.toml`; `scenarios/engineering/code_intelligence_mcp_real_query.toml`; `scenarios/engineering/code_intelligence_provider_unavailable.toml`; `scenarios/engineering/code_intelligence_read_only_counters.toml`; `scenarios/engineering/code_intelligence_scope_escape.toml`; `scenarios/engineering/code_intelligence_scope_violation.toml`; `scenarios/engineering/code_intelligence_symbol.toml`; `scenarios/engineering/code_intelligence_workspace_escape.toml`; `scenarios/engineering/code_intelligence_write_method_denied.toml` |
| 24 | `docs/WINDOWS_TUN_DESIGN.md`（current） | `apps/nexusd/src/config.rs`; `scenarios/platform/win_ip_route.toml` |
| 25 | `docs/e2e-test-system-contract.md`（contract） | `engineering/e2e/test-plans/tcp_termination_wireup.toml`; `engineering/nexus-harness/src/commands.rs`; `engineering/nexus-harness/src/scenario.rs` |
| 26 | `docs/foundation/DESIGN.md`（current） | `apps/nexusd/src/nat_stun.rs`; `apps/nexusd/src/nat_turn.rs`; `crates/nexus-domain/src/lib.rs`; `crates/nexus-projection/src/egress.rs`; `crates/nexus-projection/src/lib.rs`; `crates/nexus-projection/src/routing.rs`; `crates/nexus-projection/src/transport.rs`; `scenarios/product/discovery_mdns.toml`; `scenarios/product/discovery_static.toml`; `scenarios/product/fabric_conn_basic.toml`; `scenarios/product/fabric_conn_roam.toml`; `scenarios/product/fabric_egress_basic.toml`; `scenarios/product/fabric_egress_domain.toml`; `scenarios/product/fabric_egress_real_udp.toml`; `scenarios/product/fabric_egress_remote.toml`; `scenarios/product/fabric_egress_tcp.toml`; `scenarios/product/fabric_over_proxy.toml`; `scenarios/product/fabric_path_basic.toml`; `scenarios/product/fabric_path_rebind.toml`; `scenarios/product/fabric_path_roam.toml`; `scenarios/product/fabric_process_qos.toml`; `scenarios/product/fabric_projection_basic.toml`; `scenarios/product/fabric_projection_roam.toml`; `scenarios/product/fabric_semantic_ingress.toml`; `scenarios/product/fabric_tun_device.toml`; `scenarios/product/fabric_turn_relay.toml`; `scenarios/product/path_fallback.toml`; `scenarios/product/path_fallback_skip.toml`; `scenarios/product/path_predict_ewma.toml`; `scenarios/product/path_race.toml`; `scenarios/product/plugin_dial_ss.toml`; `scenarios/product/plugin_dial_unknown.toml`; `scenarios/product/plugin_obfs_echo.toml`; `scenarios/product/proxy_transport.toml`; `scenarios/product/proxy_transport_ss.toml`; `scenarios/product/proxy_transport_trojan.toml`; `scenarios/product/proxy_transport_trojan_tls.toml` |
| 27 | `docs/foundation/NAT-TRAVERSAL-CONTRACT.md`（contract） | `crates/nexus-nat-traversal/src/lib.rs` |
| 28 | `docs/protocols/anytls.md`（current） | `crates/nexus-outbound-anytls/src/lib.rs` |
| 29 | `docs/protocols/hysteria2.md`（current） | `crates/nexus-outbound-hysteria2/src/lib.rs` |
| 30 | `docs/protocols/interop/MATRIX.md`（current） | `scripts/interop/recompute-verdicts.py` |
| 31 | `docs/protocols/interop/NEXT-STEPS.md`（current） | `scripts/interop/recompute-verdicts.py` |
| 32 | `docs/protocols/interop/fix/hysteria2/root-cause.md`（archive） | `scripts/interop/recompute-verdicts.py`（fix_dir.glob("*/root-cause.md") 动态列举） |
| 33 | `docs/protocols/interop/fix/shadowsocks/root-cause.md`（archive） | `scripts/interop/recompute-verdicts.py`（fix_dir.glob("*/root-cause.md") 动态列举） |
| 34 | `docs/protocols/interop/fix/transport/root-cause.md`（archive） | `scripts/interop/recompute-verdicts.py`（fix_dir.glob("*/root-cause.md") 动态列举） |
| 35 | `docs/protocols/interop/fix/trojan/root-cause.md`（archive） | `scripts/interop/recompute-verdicts.py` |
| 36 | `docs/protocols/interop/fix/vless/root-cause.md`（archive） | `scripts/interop/recompute-verdicts.py`（fix_dir.glob("*/root-cause.md") 动态列举） |
| 37 | `docs/protocols/vless.md`（current） | `crates/nexus-outbound-vless/src/lib.rs` |
| 38 | `engineering/e2e/acceptance_todo.md`（current） | `engineering/e2e/_render_coverage.py` |
| 39 | `engineering/e2e/coverage_audit.md`（current） | `.pee/runs/2026-10-16-e2e-test-system/feature-list.json`（artifact 字段） |
| 40 | `engineering/e2e/coverage_matrix.md`（current） | `engineering/e2e/_render_coverage.py` |
| 41 | `scenarios/fixtures/n3-12-requester/README.md`（代码内嵌文档） | `docs/recovery/2026-10-21/printed-path-coverage.json`（path）; `docs/recovery/2026-10-21/source-integration-manifest.json`（repo_path） |
| 42 | `tests/README.md`（代码内嵌文档） | `crates/nexus-session/Cargo.toml`; `tests/concurrency/cancellation_shutdown_race.rs` |

### 3.C 其他文档引用（markdown 链接 / 行内代码路径）

| # | 被引用文件（类别） | 引用方文档 |
|---|---|---|
| 1 | `.agents/skills/nexus-task/SKILL.md`（代码内嵌文档） | `.agents/skills/README.md`（行内代码）; `AGENTS.md`（行内代码）; `DEVELOPMENT.md`（行内代码）; `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md`（行内代码）; `docs/DOCUMENTATION-ARCHITECTURE.md`（行内代码）; `engineering/sandbox-env-guard/quality/RUBRIC.md`（行内代码） |
| 2 | `.githooks/README.md`（代码内嵌文档） | `README.md`（链接） |
| 3 | `.grill/decisions.md`（archive） | `.grill/spec-draft.md`（行内代码） |
| 4 | `Nexus_Unified_System_Design_Specification_v9.md`（baseline） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 5 | `README.md`（current） | `FILE_MANIFEST.md`（行内代码）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码）; `engineering/plugins/plugin-contract.md`（行内代码）; `engineering/sandbox-env-guard/quality/RUBRIC.md`（行内代码） |
| 6 | `apps/nexus-platform-host/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 7 | `benches/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 8 | `crates/nexus-auth/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码）; `docs/N3-13A-BOUNDED-MTLS-CONTRACT-DRAFT.md`（行内代码） |
| 9 | `crates/nexus-compute/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 10 | `crates/nexus-connectivity/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 11 | `crates/nexus-delivery/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 12 | `crates/nexus-diagnostics/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 13 | `crates/nexus-discovery/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 14 | `crates/nexus-dns/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 15 | `crates/nexus-fabric/MODULE.md`（代码内嵌文档） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `.grill/decisions.md`（行内代码）; `.grill/spec-draft.md`（行内代码）; `docs/N3-13A-BOUNDED-MTLS-CONTRACT-DRAFT.md`（行内代码） |
| 16 | `crates/nexus-ingress/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 17 | `crates/nexus-measurement/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 18 | `crates/nexus-nat-quality/INTERFACE-TRACK1.md`（代码内嵌文档） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 19 | `crates/nexus-nat-traversal/MODULE.md`（代码内嵌文档） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 20 | `crates/nexus-nat-wireup/MODULE.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-02-nat-quality-crate-placement.md`（行内代码）; `docs/foundation/NAT-TRAVERSAL-STALE.md`（行内代码） |
| 21 | `crates/nexus-network/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 22 | `crates/nexus-outbound-trojan/MODULE.md`（代码内嵌文档） | `.agents/code-intelligence-followups.md`（行内代码）; `.agents/code-intelligence-phase-2-4-plan.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md`（行内代码）; `.agents/provider-daemon-and-result-cache-plan.md`（行内代码）; `.agents/skills/nexus-contract-first/SKILL.md`（行内代码）; `AGENTS.md`（行内代码）; `FILE_MANIFEST.md`（行内代码）; `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md`（行内代码）; 等共 13 处 |
| 23 | `crates/nexus-path/MODULE.md`（代码内嵌文档） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码）; `docs/foundation/PATH-LAYER-PHASE2.md`（行内代码） |
| 24 | `crates/nexus-planner/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 25 | `crates/nexus-platform-android/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 26 | `crates/nexus-platform-ios/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 27 | `crates/nexus-platform-macos/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 28 | `crates/nexus-platform-windows/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 29 | `crates/nexus-policy/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 30 | `crates/nexus-proto/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 31 | `crates/nexus-proxy/MODULE.md`（代码内嵌文档） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 32 | `crates/nexus-registry/MODULE.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-03-n2-p04-session-use.md`（行内代码）; `FILE_MANIFEST.md`（行内代码） |
| 33 | `crates/nexus-service/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 34 | `crates/nexus-transport/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 35 | `crates/nexus-web-gateway/MODULE.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-11-ice-host-candidate-bind-set-equality.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码） |
| 36 | `crates/nexus-web-gateway/USER_MANUAL.md`（代码内嵌文档） | `README.md`（行内代码）; `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md`（行内代码） |
| 37 | `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-11-datachannel-label-routing-version-skew.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-dataview-setuint64-dual-side-fixture.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-harness-dirty-working-tree-digest-blind.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-ice-host-candidate-bind-set-equality.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-panic-abort-external-arithmetic-overflow.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-resource-quota-audit-before-independent-review.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-single-loop-send-queue-head-blocking.md`（行内代码）; 等共 11 处 |
| 38 | `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-11-datachannel-label-routing-version-skew.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-dataview-setuint64-dual-side-fixture.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-harness-dirty-working-tree-digest-blind.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-ice-host-candidate-bind-set-equality.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-resource-quota-audit-before-independent-review.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码）; `crates/nexus-web-gateway/docs/README.md`（行内代码） |
| 39 | `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-11-datachannel-label-routing-version-skew.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-dataview-setuint64-dual-side-fixture.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-libssh2-sftp-readdir-lstat-cfg-gates.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-panic-abort-external-arithmetic-overflow.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-resource-quota-audit-before-independent-review.md`（行内代码）; `.agents/knowledge/entries/2026-10-11-single-loop-send-queue-head-blocking.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码）; `crates/nexus-web-gateway/docs/README.md`（行内代码） |
| 40 | `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（代码内嵌文档） | `.agents/knowledge/entries/2026-10-11-pre-push-stale-tombstone-after-every-verify.md`（行内代码）; `crates/nexus-web-gateway/docs/README.md`（行内代码） |
| 41 | `docs/CLI_FRONTEND_DESIGN.md`（archive） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码）; `docs/USER_MANUAL.md`（行内代码） |
| 42 | `docs/DEVELOPMENT-PROCESS.md`（current） | `README.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 43 | `docs/DOC-AUDIT-2026-10-06.md`（archive） | `docs/PROJECT-STATUS.md`（行内代码） |
| 44 | `docs/DOCUMENTATION-ARCHITECTURE.md`（current） | `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md`（行内代码）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码）; `docs/PROJECT-STATUS.md`（行内代码） |
| 45 | `docs/N3-1-IMPLEMENTATION.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 46 | `docs/N3-10-OPERATOR-GRANT-CONTRACT.md`（contract） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接） |
| 47 | `docs/N3-2-IMPLEMENTATION.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 48 | `docs/N3-3-LINUX-EXECUTOR.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 49 | `docs/N3-3-RUNTIME-FOUNDATION.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 50 | `docs/N3-4-ARTIFACT-DELIVERY.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 51 | `docs/N3-5-PARALLEL-PLAN.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `.agents/knowledge/entries/2026-10-04-n3-requester-scope-and-recovery-lease.md`（行内代码） |
| 52 | `docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md`（contract） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `.agents/knowledge/entries/2026-10-04-n3-localapi-and-mutual-auth-boundaries.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md`（行内代码）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码）; `docs/N3-6-PARALLEL-PLAN.md`（行内代码） |
| 53 | `docs/N3-7-ENGINEERING-PLAN.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `.agents/knowledge/entries/2026-10-05-worktree-hooks-and-test-binaries.md`（行内代码） |
| 54 | `docs/N3-8-CAPACITY-SESSION-CONTRACT.md`（contract） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码） |
| 55 | `docs/N3-9-ARTIFACT-CLI-CONTRACT.md`（contract） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`（行内代码） |
| 56 | `docs/N3-MODEL-CONTRACT.md`（contract） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `ARCHITECTURE.md`（行内代码）; `PRODUCT.md`（行内代码）; `apps/nexus/MODULE.md`（行内代码）; `crates/nexus-compute/MODULE.md`（行内代码）; `crates/nexus-control-api/MODULE.md`（行内代码）; `crates/nexus-domain/MODULE.md`（行内代码）; `crates/nexus-storage/MODULE.md`（行内代码）; 等共 12 处 |
| 57 | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（current） | `docs/recovery/2026-10-20/README.md`（链接）; `docs/recovery/2026-10-21/README.md`（链接） |
| 58 | `docs/PROJECT-STATUS.md`（current） | `README.md`（链接）; `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 59 | `docs/USER_MANUAL.md`（current） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 60 | `docs/baselines/README.md`（baseline） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 61 | `docs/baselines/v9-design-spec.md`（baseline） | `docs/PROJECT-STATUS.md`（行内代码）; `docs/baselines/README.md`（行内代码） |
| 62 | `docs/baselines/whitepaper-v1.0-product.md`（baseline） | `docs/PROJECT-STATUS.md`（行内代码）; `docs/baselines/README.md`（行内代码） |
| 63 | `docs/bugfix/path-planner-p0-amendments.md`（archive） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 64 | `docs/foundation/NAT-TRAVERSAL-DESIGN.md`（current） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码）; `docs/foundation/NAT-TRAVERSAL-CONTRACT.md`（行内代码） |
| 65 | `docs/foundation/NAT-TRAVERSAL-STALE.md`（contract） | `docs/foundation/NAT-TRAVERSAL-CONTRACT.md`（行内代码） |
| 66 | `docs/foundation/PATH-LAYER-PHASE2.md`（archive） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 67 | `docs/foundation/PROJECTION-LAYER-PHASE3.md`（archive） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 68 | `docs/foundation/PROJECTION-ROUTING-PHASE3B1.md`（archive） | `docs/DOC-AUDIT-2026-10-06.md`（行内代码） |
| 69 | `docs/protocols/bootstrap-join/01-design-v1-draft.md`（archive） | `docs/protocols/bootstrap-join/README.md`（链接） |
| 70 | `docs/protocols/bootstrap-join/02-review.md`（archive） | `docs/protocols/bootstrap-join/README.md`（链接） |
| 71 | `docs/protocols/bootstrap-join/03-design-v2-final.md`（current） | `docs/protocols/bootstrap-join/README.md`（链接） |
| 72 | `docs/protocols/interop/prediction-check.md`（archive） | `docs/protocols/interop/NEXT-STEPS.md`（链接） |
| 73 | `docs/recovery/2026-10-20/README.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接） |
| 74 | `docs/recovery/2026-10-21/README.md`（archive） | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md`（链接）; `docs/recovery/2026-10-20/README.md`（链接） |
| 75 | `engineering/evidence-schema/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 76 | `engineering/nexus-harness/fixtures/code-intel/MODULE.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 77 | `engineering/plugins/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 78 | `engineering/plugins/plugin-contract.md`（contract） | `FILE_MANIFEST.md`（行内代码）; `engineering/plugins/README.md`（行内代码） |
| 79 | `fuzz/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 80 | `fuzz/fuzz_targets/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 81 | `scenarios/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码）; `engineering/e2e/coverage_audit.md`（行内代码） |
| 82 | `tests/concurrency/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 83 | `tests/integration/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |
| 84 | `tests/regression/README.md`（代码内嵌文档） | `FILE_MANIFEST.md`（行内代码） |

## 4. 汇总统计

| 类别 | 数量 |
|---|---|
| baseline（基线） | 4 |
| contract（契约） | 17 |
| current（现行） | 29 |
| 代码内嵌文档 | 86 |
| archive（归档） | 154 |
| **合计** | **290** |

「不可轻移」合计 **214** 份（第 3 节，含 3.A 通配组 117 份、3.B 显式引用 42 份、3.C 文档间引用 84 份；三类有重叠，过去重后为 214）。

### current 超限说明与取舍建议

current 类判定为 **29 份**，超过「总量控制在 10 份以内」的目标。超限主因：现行有效的设计文档（foundation/protocols/tracing）、按源码实证的产品/用户文档、机器生成的覆盖报告均被计入 current。取舍建议如下（供人工裁决）：

**建议保留进入 current/ 的 10 份（门面 + 状态 + 流程）：**

| # | 文件 | 理由 |
|---|---|---|
| 1 | `README.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 2 | `AGENTS.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 3 | `CONTRIBUTING.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 4 | `DEV-ENV.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 5 | `FILE_MANIFEST.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 6 | `docs/USER_MANUAL.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 7 | `docs/DOCUMENTATION-ARCHITECTURE.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 8 | `docs/PROJECT-STATUS.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 9 | `docs/DEVELOPMENT-PROCESS.md` | 入口/制度/环境/导航/状态/流程类门面文档 |
| 10 | `docs/DAEMON_ARCHITECTURE.md` | 入口/制度/环境/导航/状态/流程类门面文档 |

**建议移出 current/ 的 19 份及处置方向：**

| # | 文件 | 建议处置 |
|---|---|---|
| 1 | `docs/CODE-INTELLIGENCE-KNOWN-ISSUES.md` | 并入 current 子层「状态清单」或与 PROJECT-STATUS 合并 |
| 2 | `docs/N3-RECOVERY-FUNCTION-SUMMARY.md` | 同上；属阶段性恢复总结，可随恢复归档 |
| 3 | `docs/product/product-document.md` | 与 PRODUCT.md/白皮书三源冲突（C3），合并或归档 |
| 4 | `docs/product/user-manual.md` | 与 docs/USER_MANUAL.md 双源冲突（C2），二选一 |
| 5 | `docs/foundation/DESIGN.md` | 设计类；建议设 current 子层 designs/ 或并入 contracts 设计基线区 |
| 6 | `docs/foundation/NAT-TRAVERSAL-DESIGN.md` | 设计类；已被 v1.1 合同冻结吸收，建议并入 contracts 配套 |
| 7 | `docs/WINDOWS_TUN_DESIGN.md` | 设计类；建议并入 designs 子层 |
| 8 | `docs/protocols/bootstrap-join/03-design-v2-final.md` | 设计定稿；建议并入 designs 子层 |
| 9 | `engineering/TRACING.md` | 横切设计；建议并入 designs 子层 |
| 10 | `docs/protocols/anytls.md` | 协议参考；随 outbound crate 维护，可下移为代码内嵌或设 references/ 子层 |
| 11 | `docs/protocols/hysteria2.md` | 同上 |
| 12 | `docs/protocols/vless.md` | 同上 |
| 13 | `docs/protocols/AVAILABILITY.md` | 状态汇总；与 MATRIX 同层，设 interop/ 子层 |
| 14 | `docs/protocols/interop/MATRIX.md` | 机器生成物；保留原地由 recompute-verdicts.py 继续生成 |
| 15 | `docs/protocols/interop/NEXT-STEPS.md` | 与 MATRIX/fix 根因同层，设 interop/ 子层 |
| 16 | `docs/protocols/bootstrap-join/README.md` | 索引；随 bootstrap-join 子层 |
| 17 | `engineering/e2e/acceptance_todo.md` | 生成物；保留原地由 _render_coverage.py 继续生成 |
| 18 | `engineering/e2e/coverage_audit.md` | 报告快照；可归档或保留原地 |
| 19 | `engineering/e2e/coverage_matrix.md` | 生成物；保留原地由 _render_coverage.py 继续生成 |

## 5. 冲突项（需人工裁决）

| # | 冲突 | 涉及路径 |
|---|---|---|
| C1 同名多版本/内容重复：两份内容基本一致的「Nexus 统一系统设计规范 v9」（均自称 Final Design Baseline，28485B vs 28489B，开头逐字相同） | `Nexus_Unified_System_Design_Specification_v9.md`、`docs/baselines/v9-design-spec.md` |
| C2 用户手册双源：两份用户手册基线 commit 不同（`67a75ff` vs `ced3b7a`），口径不同（命令走查 vs 函数体实证） | `docs/USER_MANUAL.md`、`docs/product/user-manual.md` |
| C3 产品描述三源：白皮书（基线，自称优先级最高）/ PRODUCT.md（harness 消费的工程契约）/ product-document.md（自称不采信任何 .md 的源码实证），三者结论口径可能互相矛盾 | `docs/baselines/whitepaper-v1.0-product.md`、`PRODUCT.md`、`docs/product/product-document.md` |
| C4 NAT 设计版本链自相矛盾：DESIGN v0.1 自称「可进合同阶段」，但 STALE 登记表已宣布 design §3/§5/§7 旧措辞 STALE、相关 API 已退役；CONTRACT v1.1 与 DESIGN v0.1 并存 | `docs/foundation/NAT-TRAVERSAL-DESIGN.md`、`docs/foundation/NAT-TRAVERSAL-CONTRACT.md`、`docs/foundation/NAT-TRAVERSAL-STALE.md` |
| C5 审计计数过时：DOC-AUDIT 记录 276 个 .md（2026-10-06 时点），与现存 290 不一致；其「可删 23」等结论未反映后续 recovery 工作 | `docs/DOC-AUDIT-2026-10-06.md`（对照现存全部 290 个 .md） |
| C6 文件清单计数漂移：FILE_MANIFEST 自述「文件数 195」且历史多次漂移修补（137→148→172→174→193），与 master 实际 1623 个文件的口径需人工确认 | `FILE_MANIFEST.md` |
| C7 bootstrap-join 版本基准矛盾：v1 自称基线 `bb6201b`，评审与 v2 均以 `cda5f21` 为准；README 称 v1 仅历史留档但 01 文件仍标注「当前」路径对应 | `docs/protocols/bootstrap-join/01-design-v1-draft.md`、`docs/protocols/bootstrap-join/02-review.md`、`docs/protocols/bootstrap-join/03-design-v2-final.md`、`docs/protocols/bootstrap-join/README.md` |
| C8 明确的文档冲突声明：provider-daemon 计划自称「设计期的历史文档」，四处被后续裁决取代，与 harness MODULE.md 冲突时以 MODULE.md 为准 | `.agents/provider-daemon-and-result-cache-plan.md`、`engineering/nexus-harness/MODULE.md` |
| C9 互操作结论多轮次并存：prediction-check（fixes-1 轮次）、MATRIX（fixes-2+3 合并轮次）、NEXT-STEPS（人工路线）、AVAILABILITY（汇总）各自记录不同轮次 verdict，SS/Hy2/Trojan 结论口径不一 | `docs/protocols/interop/prediction-check.md`、`docs/protocols/interop/MATRIX.md`、`docs/protocols/interop/NEXT-STEPS.md`、`docs/protocols/AVAILABILITY.md` |
| C10 状态文档双 current：两份 frontmatter status: current 文档，verified-against 分别为 `b9ae124` 与 `dbb511a`，核实基线不同 | `docs/PROJECT-STATUS.md`、`docs/N3-RECOVERY-FUNCTION-SUMMARY.md` |

---

*本清单由只读分析生成：全部判定基于 master HEAD `c04b409` 的实际文件内容、frontmatter/标题自我声明、 harness.toml/CI/脚本/场景配置/manifest 的路径引用证据与文档间链接证据；未对仓库做任何写操作。*
