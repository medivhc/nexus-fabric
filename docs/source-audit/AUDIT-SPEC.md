# Nexus-Fabric 纯源码审计 — 共享口径规格（所有分片必须遵守）

## 0. 仓库事实（Organizer 已核实）
- 仓库根：`/home/user/Doubao/chats/38445294397368066/nexus-fabric`
- HEAD：`e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`，工作区干净
- 规模：workspace 成员 **51 个** = 3 apps（apps/nexus、apps/nexusd、apps/nexus-platform-host）+ 47 crates（crates/）+ engineering/nexus-harness
- 分片行数总和 200,336 行 .rs（另有非成员目录 engineering/evidence-schema、engineering/plugins、engineering/verifiers，不含 .rs）
- 工具链：cargo/rustc 1.99 不在默认 PATH，命令前先 `export PATH="$HOME/.cargo/bin:$PATH"`

## 1. 事实来源（最高优先级硬约束）
1. **禁止打开、阅读、引用任何 `.md` / `.markdown` 文件**来理解项目——包括根目录与各级子目录的 AGENTS.md、README.md、ARCHITECTURE.md、PRODUCT.md、DEVELOPMENT.md、DEV-ENV.md、ENVIRONMENT.md、FILE_MANIFEST.md、设计规格 .md、docs/ 下全部、每个 crate 的 MODULE.md、.agents/ 下全部 .md。用户明确声明文档都是错的。
2. 唯一事实来源：`*.rs` 源码（主）、`Cargo.toml`/`Cargo.lock`（workspace 拓扑、依赖、features、[[bin]]）、`harness.toml`、`policies/*.toml`、`scenarios/*.toml`、`configs/`、`.json`/`.py` 等机器可执行制品。
3. 严格区分：toml 中声明的场景/门禁/架构规则只是**机器配置声明（期望）**；功能是否实现一律以 .rs 代码为准。声明了但代码无对应实现的，必须写"**声明未落地**"并给出 toml 位置 + 代码缺失证据。
4. 源码注释中若引用文档编号（§16、P1-x、N2/N3 等），只记录"代码注释自称实现了 X"，**不得**引用文档内容佐证。
5. 代码看不出的结论写"**源码中无法确认**"，禁止用文档/常识/名字臆测补全。

## 2. 出处格式（强制）
每个事实结论必须带源码出处，格式 `相对路径:行号`，例如 `apps/nexus/src/n2_store.rs:142`。行号必须真实（用 `Read`/`grep -n` 核对），禁止估算。

## 3. 实现度判定（每个 crate/模块必须四选一，附证据行号）
- `implemented`：有真实逻辑，且存在被调用路径（给出调用方位置）。
- `partial`：主路径存在但有明确缺口，必须说明缺口（哪些分支/命令/能力缺失或空转）。
- `stub`：含 `unimplemented!`/`todo!`/`panic!` 占位、空函数体、占位返回、硬编码 `Err(Unsupported)`/"not supported"、只记日志不做事等。
- `dead`：代码存在但全仓无任何调用方（用 rg 验证无调用路径，注意区分 re-export 与真正调用）。

警惕：stub 少不代表完整。重点排查"实现但空转"：函数签名齐全但内部只 `tracing::info!` 后返回 Ok(())、返回硬编码假数据、match 分支全映射到 Unsupported、命令接线了但 handler 是空壳。

## 4. 注释错误记录格式（写入 07 分片片段）
找出 `//`、`///`、`//!` 注释与代码实际行为不符之处，每条必须包含：
- 严重度：`high`（注释描述的流程/不变量/错误分类与实现矛盾，会误导调用者）/ `medium`（字段语义、参数、返回值描述过时或错误）/ `low`（措辞、拼写、注释提到的名称已不存在）
- 位置：`文件:行号`
- 注释原文引用（逐字，用引号）
- 代码事实引用（`文件:行号` + 关键代码片段）
- 不符点说明（一句话）
范围包括：注释描述的流程与实现矛盾、注释声称的保证代码不满足、注释提到的函数/参数/字段已不存在、doc comment 示例与签名不符。**宁缺毋滥，每条必须可复核**；注释只是含糊但不算错的不要收录。

## 5. 每个分片必须产出的文件（全部中文、Markdown、UTF-8）
设分片编号 X（A/B/C/D/E）、片区文档编号 N（01..05）：
1. 主文档：`/home/user/Doubao/chats/38445294397368066/project-state-audit/0N-<slug>.md`
2. 矩阵片段：`/home/user/Doubao/chats/38445294397368066/project-state-audit/fragments/06-X.md`
3. 注释错误片段：`/home/user/Doubao/chats/38445294397368066/project-state-audit/fragments/07-X.md`
4. 复核日志片段：`/home/user/Doubao/chats/38445294397368066/project-state-audit/fragments/08-X.md`

### 5.1 每篇文档头部必须逐字包含
> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。

### 5.2 主文档结构（每个 crate 一节，不得缺漏）
- 片区范围与行数总表
- 每个 crate/成员一节，含：
  - 实际职责（**从代码推断**，不得照抄 crate 名/注释）
  - 关键类型 / pub API / 入口（带行号）
  - 依赖关系（workspace 内依赖以该 crate Cargo.toml 为准 + 关键第三方依赖及用途）
  - 实现度判定 + 证据行号
  - stub / TODO / 空转 / 硬编码清单（逐条行号 + 代码片段）
  - 测试：`#[test]`/`#[tokio::test]` 总数（用 rg 实测）、tests/ 目录情况、测试实际覆盖的内容（读测试代码后概括，禁止只看测试名）
- 片区内跨 crate 调用主干（谁调谁、通过什么 trait/API，带行号）
- 片区小结：片区真实能力与最大缺口

### 5.3 06 矩阵片段格式
一级标题标明分片；一张 Markdown 表，每个成员一行：
`| crate/成员路径 | .rs 行数 | 实际职责（一句话） | 实现度 | 关键缺口 | 关键证据（文件:行号） |`
另在表后列"本片区：配置声明但代码未落地"清单（toml 位置 + 说明）。

### 5.4 07 片段格式
按 high→medium→low 排序，每条按第 4 节五要素。若某分片确实未发现，写"本分片未发现可确证的注释错误"并说明检索方法。

### 5.5 08 复核日志格式
逐条记录：回源核验了哪些结论（至少每个 crate 抽样回读 5 个关键结论的出处行；**所有 stub/完成度判定 100% 回验**）、抽样方法、发现并修正了什么（写清修正前后）、仍无法确认的点。必须是真实过程记录。

## 6. 工作方法（防止上下文丢失）
- 大文件（如 apps/nexus/src/lib.rs 11,841 行、apps/nexus/src/main.rs 1,908 行、connectivity、projection 的大文件）**必须实际读完**，可分段 Read（每段 ≤2000 行），禁止只看文件名或开头猜职责。
- 每读完一个文件/一批文件，立即把带行号的结构化笔记追加写入自己的 scratch 文件（如 `/home/user/Doubao/chats/38445294397368066/project-state-audit/fragments/scratch-X.md`），再继续——避免上下文压缩丢结论。
- 常用检索：`rg -n "unimplemented!|todo!|unreachable!" <dir>`、`rg -n "not supported|unsupported|Unsupported" <dir>`、`rg -n "#\[test\]|#\[tokio::test\]" <dir> | wc -l`、`rg -n "fn " ` 定位调用关系。
- 调用方验证：判定 dead/implemented 前用 rg 全仓搜索该 API/类型名。

## 7. 只读审计红线
- 禁止 git commit/push/checkout/branch/rebase/reset；禁止修改仓库内任何文件；禁止启动服务/网络监听；禁止跑全量 `cargo test`。
- 允许：读文件、rg/grep、`cargo check -p <crate>`、`cargo test -p <crate> <具体测试名>` 做针对性验证。
- 所有新文件只能写到 `/home/user/Doubao/chats/38445294397368066/project-state-audit/` 下。

## 8. 完成标准
本分片分配的每个 workspace 成员都有主文档章节 + 06 行条目；所有结论带可复核行号；实现度判定有证据；注释错误每条可复核；08 记录真实复核（含修正项）；文档自包含——读者不读仓库任何 .md 即可理解。
