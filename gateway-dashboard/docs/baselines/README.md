# 基线文档（Baselines）

本目录存放 Nexus 的两份**外部基线文档**（2026-10-01 用户指定，复制入仓以便版本对照）。
它们是产品与设计的真相来源，优先级高于仓库内其他非契约描述。

| 文档 | 文件 | 角色 |
|---|---|---|
| 产品白皮书 v1.0 | `whitepaper-v1.0-product.md` | **产品定义基线**：N1/N2/N3 三层、Resource/Provider/Session/Task 等核心概念。产品概念冲突时以它为准。 |
| v9 统一系统设计规范 | `v9-design-spec.md` | **技术设计基线**（Final Design Baseline）：Resource/Provider/Node/Intent/Constraint/Plan/Session/Measurement 核心对象，Resource+Intent → … → Execute → Observe+Adapt 闭环。架构术语以它为准。 |

## 使用规则

- 产品概念问题 → 先查白皮书；系统架构/实现术语 → 先查 v9。
- 两者角色互补：白皮书管"是什么、为什么"，v9 管"怎么建"。
- 仓库内的 `PRODUCT.md` / `ARCHITECTURE.md` 是工程契约，
  若与基线冲突，以基线为准并走 `requirement-change` 流程对齐。
- 基线文档本身**不直接编辑**；新版本到达时整体替换并记录日期。
