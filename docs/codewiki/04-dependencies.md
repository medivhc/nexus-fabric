# 04 · 依赖关系（Dependencies）

> 依据：[ARCHITECTURE.md §3](../../ARCHITECTURE.md)（编译依赖契约）、
> [policies/architecture.toml](../../policies/architecture.toml)、
> [policies/dependencies.toml](../../policies/dependencies.toml)、
> [policies/deny.toml](../../policies/deny.toml)、各 crate `Cargo.toml` / `MODULE.md`（实测于 `585e910`）。
> 文本契约与机器 Policy 双重约束；冲突时以契约为准。

## 1. 编译依赖总图（ARCHITECTURE §3 契约）

`A --> B` 表示 A 在编译期依赖 B。按层自底向上：

```text
┌─ 领域核心（零 I/O、纯类型）────────────────────────────────┐
│  nexus-domain（根基层，几乎所有 crate 的公共词汇，零依赖）    │
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

- `nexus-flow-session --> nexus-domain / nexus-policy / nexus-planner / nexus-session / nexus-network`（只读）
- `nexus-scheduler`：**零 Nexus 内部依赖**（`allowed_internal_dependencies = []`）
- `nexus-proxy-config`：portable-core 配置层（实现为零依赖）
- `nexus-proxy --> nexus-ingress / nexus-connectivity`（复用 FlowContext 与 LinkActivator）
- `nexus-fabric` / `nexus-plugin` / `nexus-path` / `nexus-web-gateway`：零 Nexus 内部依赖

## 2. 禁止依赖边（架构红线，machine-enforced）

```text
nexus-network     -X-> nexus-ingress          （ingress 不是 network 私有子件）
nexus-domain      -X-> nexus-platform-*       （Portable Core 不碰平台 API）
nexus-delivery    -X-> nexus-workspace / nexus-compute   （底座不反向依赖业务域）
production crates -X-> engineering harness    （运行时与工程平面正交）
platform adapters -X-> higher-level domain runtimes
nexus-proxy       -X-> nexus-network / nexus-service / nexus-workspace / nexus-compute
nexus-projection  -X-> nexus-proxy / tokio    （新决策经 nexus-domain::RuleEngine trait）
nexus-plugin      -X-> nexus-outbound-*       （依赖倒置：出站依赖插件，不反向）
```

`policies/architecture.toml` 以 `unlisted_internal_dependencies = "deny"` 闭集执行；
另含 `[resource_kind_neutrality]`：registry/planner/session/auth 四 crate 禁止按资源类型
分叉行为（harness gate `resource-type-neutrality` 机器检查，fail-closed）。
**禁边核查结论（实测）**：以上红线全部通过——nexus-network 无 ingress 边、
nexus-projection 无 proxy/tokio 边、delivery 无业务反向边。

## 3. 实测内部依赖（各 Cargo.toml 汇总）

| crate | Cargo 实际 nexus-\* 依赖 | 与契约的出入 |
|---|---|---|
| nexus-domain / nexus-plugin / nexus-scheduler / nexus-proxy-config / nexus-path / nexus-fabric / nexus-web-gateway / nexus-proto | —（零内部依赖） | — |
| nexus-registry / nexus-auth / nexus-policy / nexus-storage / nexus-measurement / nexus-diagnostics / nexus-service / nexus-ingress / nexus-dns / nexus-control-api / nexus-delivery | nexus-domain（service 另声明 nexus-session 未用） | control-api 未引允许的 nexus-proto；service 未引 nexus-delivery |
| nexus-planner | domain, registry, measurement | 一致 |
| nexus-session | domain | 一致 |
| nexus-discovery | domain, registry, platform（**声明**） | **⚠ 源码暂未 use 三个内部 crate**（契约允许边界） |
| nexus-flow-session | domain, measurement, policy, planner, session, network | network 声明未用 |
| nexus-connectivity | platform, domain, measurement | delivery 允许未用 |
| nexus-network | domain, policy, planner, session, dns, platform | delivery 允许未用 |
| nexus-workspace | domain, session, storage, platform | delivery 允许未用 |
| nexus-compute | domain, session, workspace | delivery 允许未用 |
| nexus-workspace-intel | domain, workspace, planner, registry, storage | 一致 |
| nexus-nat-traversal | connectivity | 一致（无 MODULE.md） |
| nexus-nat-wireup | fabric, nat-traversal, connectivity（turn 仅 dev） | 一致 |
| nexus-nat-quality | fabric, path | 一致 |
| nexus-turn | fabric（仅 `UdpTransport` trait） | 一致 |
| nexus-outbound-{ss,vmess,trojan,anytls,vless,hysteria2} | connectivity（全部）；ss/trojan 另声明 plugin | **⚠ ss/trojan 的 plugin 声明未用** |
| nexus-proxy-transport | fabric（仅 trait）, outbound-ss, outbound-trojan, proxy-config | 一致 |
| nexus-proxy | domain, proxy-config, ingress, connectivity, measurement | policy/planner 声明未用 |
| nexus-projection | domain, fabric, ingress, nat-wireup, path | **⚠ nat-wireup 未列 MODULE.md Allowed**（policies 已声明） |
| nexus-platform-{linux,windows,macos,android,ios} | platform（仅此一个） | 一致（linux 的 workspace/storage 仅 dev） |
| apps/nexus（组合根） | 30+ nexus crate 纵切装配 | Cargo.toml 注释豁免：app 不在 policies crates 约束集内 |
| apps/nexusd（组合根） | 30+ nexus crate（含 flow-session/nat-\*/outbound-\*） | 同上 |
| apps/nexus-platform-host | platform + feature-gated platform-\* | 一致 |

已知"声明未用"边汇总：`service→session`、`discovery→{domain,registry,platform}`、
`flow-session→network`、`outbound-{ss,trojan}→plugin`、`control-api→proto`（未引）、
`{connectivity,network,workspace,compute,transport}→delivery`（delivery 是 7 行骨架）。
全部是"Allowed 未用满"方向，**无越界依赖**。

## 4. Portable Core（harness.toml `[portable_core]`，12 crate）

必须通过 WASI（`wasm32-wasip1`）portability gate：

```text
nexus-domain  nexus-registry  nexus-policy   nexus-auth
nexus-scheduler nexus-planner nexus-session  nexus-measurement
nexus-delivery  nexus-ingress nexus-proxy-config nexus-proxy
```

纪律：纯内存/零 I/O/`#![forbid(unsafe_code)]`；I/O 全经组合根注入
（`LatencyProbe`/`SubmitFn`/`ControlTransport`/`DiscoveryTransport`/`Resolver` 等）。

## 5. 依赖治理（policies/）

| 文件 | 作用 |
|---|---|
| [architecture.toml](../../policies/architecture.toml) | 内部依赖闭集（逐 crate `allowed_internal_dependencies` + `portable` + `layer`）、全局禁令、resource-kind-neutrality |
| [dependencies.toml](../../policies/dependencies.toml) | 第三方策略（prefer `default-features=false`、禁 unpinned git/工作区外 path、六维评审强制）+ 许可证 allowlist（MIT/Apache-2.0/BSD-2/3/0BSD/ISC/Unicode-3.0/Zlib）+ 安全 + 供应链（lockfile 必须）；`[[dependency_reviews.direct]]` 逐条记录已批准依赖（~35 条，含理由与日期） |
| [quality.toml](../../policies/quality.toml) | 编译 gate（deny_warnings/fmt/clippy）、feature matrix、portability、fast 8 gates / full 14 gates、evidence 语义、并发纪律（fire-and-forget=deny）、性能预算 |
| [deny.toml](../../policies/deny.toml) | cargo-deny 执行配置（advisories/licenses/bans/sources）；RustSec 库、yanked=deny、sources 仅 crates.io |

新增依赖必须过：architecture / feature / license / security / portability / supply-chain
六维评审，并登记入 `dependency_reviews.direct`。

## 6. 主要外部依赖（已评审）

| 依赖 | 用途 | 使用者 |
|---|---|---|
| `quinn-proto` 0.11（**[vendor 补丁](../../vendor/quinn-proto/)**） | sans-IO QUIC（修复 quinn#2658 漫游 loss-detection） | nexus-fabric、outbound-hysteria2 |
| `ring` 0.17 | 密码学（HKDF/AEAD/ed25519） | platform、connectivity、discovery、fabric、auth(sha2)… |
| `x25519-dalek` | 虚拟子网链路密钥交换 | nexus-connectivity |
| `rustls` 0.23 (+rustls-native-certs) | TLS | outbound-trojan、proxy-transport、web-gateway |
| `smoltcp` 0.12 | 用户态 TCP 终结 | nexus-projection |
| `tun-rs` 2.8 | 真实 TUN 设备 | nexus-projection |
| `fuser` 0.18 | FUSE 投影 | nexus-platform-linux |
| `str0m` / `tungstenite` / `ssh2` | WebRTC / WS / SSH | nexus-web-gateway |
| `sha2` / `hmac` / `sha1` / `md5` | 派生与认证 | auth、turn |
| `flate2` / `lz4_flex` | 压缩（dataplane pipeline） | nexus-connectivity |
| `serde` / `serde_json` / `toml` | 序列化与配置 | 全仓（均 default-features=false 优先） |

出站协议族自身 `#![forbid(unsafe_code)]`、零 tokio（13 个传输/穿透 crate grep 零命中
tokio/async-std——全仓库同步 std + sans-IO 纪律）。

## 7. 测试与工程依赖拓扑

```text
tests/（跨 crate 并发/集成/回归）
  └─ 依赖多个 crate（session 挂 2 个竞态测试 target）
engineering/nexus-harness
  ├─ 外部进程只读：git / cargo / rustc / rust-analyzer（code intelligence）
  ├─ 第三方仅 serde_json + toml
  └─ 可写 .evidence/（其余仓库内零残留）
fuzz/（独立 cargo-fuzz 子工作区，nightly）→ policy/planner no_panic
benches/ → 驱动在 apps/nexus/examples/perf_bench.rs（harness bench gate 调用）
```

production crate 不得依赖 engineering（正交性红线）；harness 不被任何生产 crate 依赖。
