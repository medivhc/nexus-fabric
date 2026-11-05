# Nexus Code Wiki

> 本目录是 Nexus 仓库的 **Code Wiki**（L4 导航层派生文档）：从仓库契约与源码中提炼的
> 结构化代码文档。它的权威来源是 `PRODUCT.md` / `ARCHITECTURE.md` / `crates/*/MODULE.md`
> / `scenarios/` / `policies/`（L1 契约层），**发生冲突时一律以契约为准**。
>
> 生成基线：commit `585e910`（2026-10-22）。
> 任务类型：`docs`（不修改任何产品代码、契约或 expectation）。

## 文档结构

| 文档 | 内容 | 回答的问题 |
|---|---|---|
| [01-architecture-overview.md](01-architecture-overview.md) | 项目整体架构 | Nexus 是什么？系统分几层？数据怎么流？ |
| [02-module-responsibilities.md](02-module-responsibilities.md) | 主要模块（crate）职责 | 每个 crate 负责什么、不负责什么？ |
| [03-key-types-and-functions.md](03-key-types-and-functions.md) | 关键类型与函数 | 核心 struct / trait / 函数在哪、干什么？ |
| [04-dependencies.md](04-dependencies.md) | 依赖关系 | 谁依赖谁？哪些边被禁止？外部依赖有哪些？ |
| [05-running-and-development.md](05-running-and-development.md) | 运行方式与开发流程 | 怎么构建、运行、测试、验证、提交？ |

## 快速入口

- 产品契约：[PRODUCT.md](../../PRODUCT.md)（17 节，含代理内核/虚拟子网/N2/N3）
- 架构契约：[ARCHITECTURE.md](../../ARCHITECTURE.md)
- 开发契约：[DEVELOPMENT.md](../../DEVELOPMENT.md)
- 工程制度：[AGENTS.md](../../AGENTS.md)
- 机器可读工程入口：[harness.toml](../../harness.toml)
- 模块契约：`crates/<crate>/MODULE.md`
- 产品级 E4 场景：[scenarios/](../../scenarios/)（314 个场景）
- 实证产品文档（按源码函数体核实）：[docs/product/](../product/)
- 用户手册：[docs/USER_MANUAL.md](../USER_MANUAL.md) / [crates/nexus-web-gateway/USER_MANUAL.md](../../crates/nexus-web-gateway/USER_MANUAL.md)
- 项目现状：[docs/PROJECT-STATUS.md](../PROJECT-STATUS.md)

## 阅读顺序建议

1. 先读 01 建立全局心智模型；
2. 按关心的域跳 02 对应层（每 crate 都链到其 `MODULE.md` 与源码）；
3. 写代码前用 03 定位关键类型/函数，用 04 核对依赖边界是否允许；
4. 动手前读 05 的构建/验证命令与门禁规则。

## 诚实性约定

本文档如实标注成熟度光谱：哪些 crate 是实心实现、哪些是编译锚点骨架
（如 `nexus-diagnostics`/`nexus-delivery`/`nexus-proto` 各仅 7 行）、
以及已知的"契约文字落后于实现"之处（见 02/04 各节备注），不把骨架描述成已实现能力。
