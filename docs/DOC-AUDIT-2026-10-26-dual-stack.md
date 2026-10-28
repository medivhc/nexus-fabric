# DOC-AUDIT 2026-10-26 — 双栈划界文档审计快照

- date: 2026-10-26
- 范围：`dual-stack-convergence` run 的 P0（文档划界）落点；**不改写**历史快照
  `docs/DOC-AUDIT-2026-10-06.md`。
- 决策记录：`docs/adr/0001-dual-stack-boundary.md`。
- 用词：状态只用四态 **保留 / 过时 / 可删 / 待定**；分层词只用 **L1–L4**
  （`docs/DOCUMENTATION-ARCHITECTURE.md` §2）。

## 冲突行与处置

| 文件 | 状态 | 冲突行 | 处置 |
|---|---|---|---|
| `crates/nexus-connectivity/MODULE.md` | 过时 | `:3-5` Responsibility 未限定运行时；`:7-9` Non-Responsibilities 未排除 N1；缺 `Lifecycle` | 改写（P0 §1.3）：Responsibility/Non-Responsibilities 限定 + 新增 `## Lifecycle` + Forbidden 加反向依赖禁令 |
| `crates/nexus-connectivity/src/lib.rs:6` | 过时 | 自称 delivery 层共享底座的定性，且引用 `ARCHITECTURE §11`（旧引用本身有误） | 改写为 v9 CLI 产品线运行时（frozen）+ 演进纪律；§11 → §6 |
| `crates/nexus-connectivity/src/**/*.rs`（22 个模块头） | 过时 | 各文件 `:3`（`routing.rs` 为 `:4`）的 "delivery 层共享底座的…" | 机械替换为 "v9 CLI 产品线运行时（frozen）的…"（仅 `//!` 行，零行为变化） |
| `ARCHITECTURE.md:150` | 过时 | "Delivery Infrastructure 被 Network/Service/Workspace/Compute 共享" | §6 正文改写为双栈划界 + 共享叶清单 |
| `ARCHITECTURE.md:254` | 过时 | "与远程资源访问闭环共享同一 Delivery Infrastructure" | 改为 "与 v9 CLI 建连路径共享 `LinkActivator`（v9 运行时）" |
| `ARCHITECTURE.md:260` | 过时 | "代理内核产品线与远程资源访问闭环共享底座但不互相调用业务逻辑" | 改为 "不互相调用业务逻辑；两者共享的仅为跨栈共享叶（见 §6）" |
| `AGENTS.md:739` | 过时 | "Connectivity 与 Transport 是共享底座" | §9 `### Delivery Infrastructure` 整体改写为分层词 + 双栈定义 |
| `AGENTS.md:2114-2123`（§29.1 表） | 保留 + 加注 | 表内 `nexus-connectivity/` 归 `agent-b` 域（`:2117`） | **不改归属**；表后补 frozen 会签 + 独立 Review 备注 |
| `crates/nexus-network/MODULE.md:173` | 过时 | "Connectivity/Transport 是共享 Delivery Infrastructure" | 改为分层词 + 双栈口径（v9 侧 `nexus-connectivity` frozen；N1 侧 fabric/path） |
| `docs/DOC-AUDIT-2026-10-06.md:89` | 过时（不改原文件） | 把 `HolePuncher::punch` 记为 `#[deprecated]`；实际已于 2026-10-18 删除 | 本快照登记为过时；P0 在 connectivity MODULE 退役记录块补复核注记 |
| `docs/DOC-AUDIT-2026-10-06.md`（nat-traversal 行） | 过时（不改原文件） | 记 "`crates/nexus-nat-traversal/`（缺 MODULE.md）"；现文件存在（113 行） | 本快照按现状登记为 **保留** |
| `docs/USER_MANUAL.md:321` | 保留 + 加注 | SDK 面（`nexus_connectivity::nat::{…}`）未标所属栈 | P1 就地加注："该 SDK 面属 v9 CLI 运行时（frozen）；新栈请用 `nexus_domain::nat`"；命令/参数正文不改 |
| `docs/foundation/NAT-TRAVERSAL-CONTRACT.md:53` | 过时 | "`[dependencies]` 为空"（实际已依赖 connectivity，P1 后依赖 domain） | P1 改为 "仅 `nexus-domain`（std-only，无第三方依赖）" |
| `docs/foundation/NAT-TRAVERSAL-CONTRACT.md:60` | 过时 | "`NatType` 复用 `nexus-connectivity::nat::NatType`" | P1 改为 `nexus-domain::nat::NatType` + "`nexus-connectivity` 以 `pub use` 保旧路径" |
| `PRODUCT.md:1349` | 过时 | "nat.rs（`nexus-connectivity::nat`：`NatType`…）" | P1 改为 `nexus-domain::nat`（`NatType`/`StunMapping`；connectivity 以 `pub use` 保旧路径；旧 `StunClient`/`HolePuncher` 退役记录保留） |
| `PRODUCT.md:497` | 待定 | `OutboundAdapter` 归属（接缝②，P2 条件项） | P2 处置；本轮不动 |
| `PRODUCT.md:1405` / `:1424` | 过时（本轮不改） | 仍把 `nat.rs` 说成 STUN 基础头原语来源；canonical codec 实为 `nexus_turn::stun`（见 `docs/USER_MANUAL.md:321`） | **只登记不改**：超出本 run P1 的文件面，避免静默扩权改 `PRODUCT.md` |
| 6 × `nexus-outbound-*/MODULE.md`（shadowsocks / vmess / trojan / anytls / vless / hysteria2） | 待定 | Allowed 段仍列 `nexus-connectivity`（接缝②） | P0 在 Forbidden 加过渡条目（目标态禁止 + 残留接缝②/P2 清除）；P2 改 Allowed 段 |
| `apps/nexusd/MODULE.md:34` | 待定 | Allowed 段 "`nexus-connectivity`（统一数据面：CAKE-like QoS）"（接缝②③） | P0 在 Forbidden 加过渡条目（②待 P2、③待 P3）；P2/P3 改 Allowed 段 |
| `crates/nexus-nat-traversal/MODULE.md` | 保留 | `## 依赖` 段 "仅 `nexus-connectivity`（`NatType`）" | P1 改为 "仅 `nexus-domain`（`NatType`）"；P0 已补过渡 Forbidden 段 |
| `crates/nexus-nat-wireup/MODULE.md` | 保留 | `:33` Allowed 列 `nexus-connectivity`（接缝①） | P1 去掉该边并加 `nexus-domain`；P0 已补过渡 Forbidden 段 |
| `docs/DOCUMENTATION-ARCHITECTURE.md:69` / `:157` | 待定 | 规定 ADR 命名 `NNNN-<slug>.md` 与"第一条 ADR 是 `0001-doc-architecture.md`" | 本 run 建立 `docs/adr/` 并占用 `0001-dual-stack-boundary.md`；`0001-doc-architecture.md` 顺延为后续编号（编号决策见 ADR 与 develop plan A5） |

## 复核注记

- `crates/nexus-connectivity/MODULE.md` 的打洞退役记录（原记载 `nat_path_decision` /
  `PathDecision` / `StunClient::detect_nat_type` 已删除）与 `docs/DOC-AUDIT-2026-10-06.md:89`
  的口径合并处置：**退役事实以代码为准**，10-06 快照的 `#[deprecated]` 说法按过时登记。
- 本快照只记录 P0 时点事实；P1/P1′/P2/P3 落地后由各自的任务更新对应行。
