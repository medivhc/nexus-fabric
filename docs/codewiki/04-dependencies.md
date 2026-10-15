# 04 · 依赖关系（Dependencies）

> 依据：[ARCHITECTURE.md §3](../../ARCHITECTURE.md)（编译依赖契约）、
> [policies/architecture.toml](../../policies/architecture.toml)、
> [policies/dependencies.toml](../../policies/dependencies.toml)、各 crate `Cargo.toml` / `MODULE.md`。
> 文本契约与机器 Policy 双重约束；冲突时以契约为准。

## 1. 编译依赖总图（ARCHITECTURE §3 契约）

`A --> B` 表示 A 在编译期依赖 B。按层自底向上：

```text
┌─ 领域核心（零 I/O、纯类型）────────────────────────────────┐
│  nexus-domain（根基层，几乎所有 crate 的公共词汇）           │
└──────────────────────────────────────────────────────────────┘
        ▲                ▲                ▲
┌───────┴──────┐ ┌───────┴──────┐ ┌───────┴──────────────────┐
│ nexus-registry│ │ nexus-policy │ │ nexus-auth / measurement │
│ nexus-session │ │              │ │ nexus-storage /          │
│ nexus-diagnostics│            │ │ nexus-control-api(→proto)│
└───────────────┘ └──────────────┘ └──────────────────────────┘

nexus-discovery     --> nexus-domain / nexus-registry / nexus-platform
nexus-planner       --> nexus-domain / nexus-registry / nexus-measurement

nexus-delivery      --> nexus-domain
nexus-connectivity  --> nexus-delivery / nexus-platform
nexus-transport     --> nexus-delivery / nexus-platform

nexus-ingress       --> nexus-domain
nexus-dns           --> nexus-domain

nexus-network       --> nexus-domain / nexus-policy / nexus-planner
                        / nexus-session / nexus-delivery / nexus-dns

nexus-service       --> nexus-domain / nexus-session / nexus-delivery
nexus-workspace     --> nexus-domain / nexus-session / nexus-delivery / nexus-storage
nexus-compute       --> nexus-domain / nexus-session / nexus-delivery / nexus-workspace

nexus-control-api   --> nexus-domain / nexus-proto
nexus-platform-<os> --> nexus-platform
```

补充（MODULE.md 声明，未列入 §3 表）：

- `nexus-flow-session --> nexus-domain / nexus-policy / nexus-planner / nexus-session / nexus-network`
- `nexus-scheduler`：**零 Nexus 内部依赖**（`allowed_internal_dependencies = []`）
- `nexus-proxy-config --> （portable-core，不依赖运行时 crate）`
- `nexus-proxy --> nexus-ingress / nexus-connectivity`（复用 FlowContext 与 LinkActivator）

## 2. 禁止依赖边（架构红线）

```text
nexus-network     -X-> nexus-ingress          （ingress 不是 network 私有子件）
nexus-domain      -X-> nexus-platform-*       （Portable Core 不碰平台 API）
nexus-delivery    -X-> nexus-workspace / nexus-compute   （底座不反向依赖业务域）
production crates -X-> engineering harness    （运行时与工程平面正交）
platform adapters -X-> higher-level domain runtimes
nexus-proxy       -X-> nexus-network / nexus-service / nexus-workspace / nexus-compute
```

额外约束（MODULE.md / ARCHITECTURE §11）：

- `nexus-network -X-> nexus-flow-session`（flow-session 是 Application 层，network 不得反向依赖）
- `nexus-compute` 不直接依赖 storage / platform / network（经组合根注入）
- `nexus-control-api` 不依赖 compute / workspace / storage 实现
- 生产 crate 不得依赖 rust-analyzer / LSP / MCP（Code Intelligence 仅属 `engineering/`）
- 工程夹具 `engineering/nexus-harness/fixtures/code-intel` 是独立 workspace，
  在根 `Cargo.toml` 中显式 `exclude`，绝不进生产依赖图

这些红线由 [policies/architecture.toml](../../policies/architecture.toml) 机器检查
（`nexus-harness verify` 的 architecture delta / policy gate）。

## 3. 实测内部依赖（各 Cargo.toml 汇总）

下表为各 crate 的 `nexus-*` 内部依赖（用于日常核对"允许边"是否被悄悄扩张）：

| crate | 内部依赖 |
|---|---|
| nexus-domain | —（零依赖根，Cargo `[dependencies]` 为空） |
| nexus-registry / nexus-policy / nexus-auth / nexus-measurement / nexus-storage / nexus-diagnostics / nexus-session / nexus-control-api / nexus-dns / nexus-ingress | nexus-domain（单依赖；control-api 另可选 nexus-proto，当前未用） |
| nexus-plugin / nexus-proxy-config / nexus-path / nexus-scheduler / nexus-proto / nexus-fabric / nexus-web-gateway | —（零内部依赖；web-gateway 连 async runtime 都没有） |
| nexus-discovery | nexus-domain, nexus-registry, nexus-platform |
| nexus-planner | nexus-domain, nexus-registry, nexus-measurement |
| nexus-delivery | nexus-domain |
| nexus-connectivity | nexus-delivery, nexus-platform, nexus-domain, nexus-measurement |
| nexus-transport | nexus-delivery, nexus-platform, nexus-proto |
| nexus-network | nexus-domain, nexus-policy, nexus-planner, nexus-session, nexus-delivery, nexus-dns, nexus-platform(VPI trait) |
| nexus-flow-session | nexus-domain, nexus-policy, nexus-planner, nexus-session, nexus-network, nexus-measurement |
| nexus-service | nexus-domain, nexus-session |
| nexus-workspace | nexus-domain, nexus-session, nexus-delivery, nexus-storage, nexus-platform |
| nexus-workspace-intel | nexus-domain, nexus-workspace, nexus-planner, nexus-registry, nexus-storage |
| nexus-compute | nexus-domain, nexus-session, nexus-workspace（注：MODULE.md Allowed 写 delivery，实际为 workspace） |
| nexus-proxy | nexus-domain, nexus-proxy-config, nexus-ingress, nexus-connectivity, nexus-measurement |
| nexus-proxy-transport | nexus-fabric, nexus-outbound-shadowsocks, nexus-outbound-trojan, nexus-proxy-config |
| nexus-outbound-{shadowsocks,vmess,trojan,anytls,vless,hysteria2} | nexus-connectivity（ss/trojan 另声明 nexus-plugin，源码暂未引用） |
| nexus-nat-traversal | nexus-connectivity |
| nexus-nat-wireup | nexus-fabric, nexus-nat-traversal, nexus-connectivity |
| nexus-nat-quality | nexus-fabric, nexus-path |
| nexus-turn | nexus-fabric（仅 `UdpTransport` trait） |
| nexus-projection | nexus-domain, nexus-fabric, nexus-ingress, nexus-path |
| nexus-platform-{linux,windows,macos,android,ios} | nexus-platform |
| nexus-fabric / nexus-web-gateway / nexus-platform-host | apps/nexus-platform-host 仅 nexus-platform |
| apps/nexusd（组合根） | 可依赖多数领域 crate（装配层豁免面最大） |
| apps/nexus | nexus-control-api 为主 + SDK 组合根装配的领域 crate |
| engineering/nexus-harness | 独立（production 不得反向依赖它） |

> 以各 crate `Cargo.toml` 与 `MODULE.md` 的 Allowed / Forbidden Dependencies 为准；
> 上表是导航速查，不是契约本身。已知契约/实现出入：`nexus-compute`（MODULE 写 delivery、
> 实际 workspace）、`nexus-control-api`（MODULE 允许 proto、当前未用）、
> `nexus-outbound-ss/trojan`（Cargo 声明 nexus-plugin 但源码未引用）。

## 4. 依赖治理（policies/）

| 策略文件 | 管什么 | 检查方式 |
|---|---|---|
| [policies/architecture.toml](../../policies/architecture.toml) | 分层、允许/禁止内部依赖边 | verify 的 architecture delta / policy gate |
| [policies/dependencies.toml](../../policies/dependencies.toml) | 第三方依赖准入（license / security / feature / 平台可移植性） | dependency delta + governance gate |
| [policies/quality.toml](../../policies/quality.toml) | 质量门禁（clippy / fmt / 测试要求） | check / verify |
| [policies/deny.toml](../../policies/deny.toml) | cargo-deny 配置（许可证、漏洞、重复依赖） | `cargo deny`（缺失时 dependency-governance 记 UNKNOWN） |

新增依赖的流程（AGENTS.md §4 dependency 任务类型）：必须过
architecture / feature / license / security / portability / supply-chain 六项 review；
第三方依赖默认 `default-features = false`。

## 5. 主要外部依赖

| 类别 | 依赖 | 使用者 |
|---|---|---|
| 异步运行时 | tokio | apps、transport、数据面 |
| QUIC | quinn / quinn-proto（**vendor 补丁**：quinn#2658 loss-detection 修复，见 [Cargo.toml](../../Cargo.toml) `[patch.crates-io]`） | transport / multipath |
| 密码学 | ring、x25519-dalek、chacha20poly1305（AEAD）、hkdf | connectivity 加密、discovery 配对、outbound 协议 |
| 序列化 | serde / serde_json / serde_yaml / toml | 配置、wire DTO、scenario |
| 压缩 | flate2（rust_backend）、lz4_flex | 数据面管线压缩 |
| 平台 | 各 OS API 绑定（Linux tun / wintun C ABI / NetworkExtension 等） | nexus-platform-* |

注意：vendor 的 `quinn-proto` 是仓库内 `[patch]` 覆盖，升级 quinn 时必须重新核对补丁。

## 6. 测试与工程依赖拓扑

```text
apps/nexus/examples/*.rs      → E4 场景的驱动程序（被 scenarios/product/*.toml 调用）
apps/nexus/tests/*.rs         → CLI/LocalAPI 集成测试
tests/concurrency/*.rs        → 跨 crate 并发竞态测试（session outcome / cancellation）
fuzz/fuzz_targets/            → policy_planner_no_panic 等
engineering/verifiers/*.py    → E4 场景的外部校验器
engineering/nexus-harness     → 驱动 scenarios/ 执行与 Evidence 生成
```

依赖方向纪律同样适用于测试：production crate 不得引用 harness；
scenario 通过**命令**（example 可执行、CLI、verifier 脚本）与产品交互。
